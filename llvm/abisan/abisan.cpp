/*
 * ABI Sanitizer
 * This is an unconventional kind of LLVM pass.
 * Basically, it instantiates a MCAsmStreamer for x86-64 that
 * statically checks for some ABI violations, and emits
 * dynamic checks when this gets hard.
 */

#include "Target/X86/MCTargetDesc/X86BaseInfo.h"
#include "Target/X86/MCTargetDesc/X86MCTargetDesc.h"
#include "Target/X86/X86.h"
#include "Target/X86/X86RegisterInfo.h"
#include "X86InstrInfo.h"
#include "abisan_runtime.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAsmStreamer.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDirectives.h"
#include "llvm/MC/MCInstBuilder.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Host.h"
#include <cctype> // for std::tolower
#include <vector>

using namespace llvm;

class ABISanFirstPassStreamer : public MCAsmStreamer {
  // This class exists to make a first pass over the .s file to collect
  // all the names of the functions we want to instrument.
public:
  DenseSet<MCSymbol *> instrumented_symbols;
  ABISanFirstPassStreamer(MCContext &Context,
                          std::unique_ptr<formatted_raw_ostream> os,
                          std::unique_ptr<MCInstPrinter> printer,
                          std::unique_ptr<MCCodeEmitter> emitter,
                          std::unique_ptr<MCAsmBackend> asmbackend)
      : MCAsmStreamer(Context, std::move(os), std::move(printer),
                      std::move(emitter), std::move(asmbackend)) {}

  bool emitSymbolAttribute(MCSymbol *Symbol, MCSymbolAttr Attribute) override {
    bool const result = MCAsmStreamer::emitSymbolAttribute(Symbol, Attribute);

    if (Attribute == MCSA_Global &&
        (!Symbol->isInSection() || Symbol->getSection().hasInstructions()) &&
        Symbol->getName().str() != "_start") { // .globl and has code and is in
                                               // an executable section, or no
                                               // section, and not _start
      instrumented_symbols.insert(Symbol);
    }
    return result;
  }
};

static DenseSet<MCRegister>
deduplicate_subregisters(DenseSet<MCRegister> const &regs,
                         MCRegisterInfo const &MRI) {
  DenseSet<MCRegister> result;
  for (auto const &r1 : regs) {
    bool is_sub = false;
    for (auto const &r2 : regs) {
      if (MRI.isSubRegister(r2, r1)) {
        is_sub = true;
        break;
      }
    }
    if (!is_sub) {
      result.insert(r1);
    }
  }

  return result;
}

static unsigned get_register_size(MCRegister const &reg,
                                  MCRegisterInfo const &MRI) {
  unsigned result = 0;
  for (auto const &RC : MRI.regclasses()) {
    if (RC.contains(reg)) {
      unsigned const size = RC.getSizeInBits();
      if (size > result) {
        result = size;
      }
    }
  }
  if (result == 0) {
    errs() << "Unable to find register class for " << MRI.getName(reg) << "!\n";
    exit(1);
  }
  return result;
}

static DenseSet<unsigned> const CALL_OPCODES{
    X86::CALL16r, X86::CALL16m, X86::CALLpcrel16,
    X86::CALL32r, X86::CALL32m, X86::CALLpcrel32,
    X86::CALL64r, X86::CALL64m, X86::CALL64pcrel32,
};

static DenseSet<unsigned> const RET_OPCODES{X86::RET16, X86::RET32, X86::RET64};

// Nonvolatile registers
static DenseSet<MCRegister> const NONVOLATILE_REGS{
    X86::RBP, X86::RBX, X86::R12, X86::R13, X86::R14, X86::R15};

// Volatile registers that are not used for return values
static DenseSet<MCRegister> const CALL_CLOBBERED_REGS{
    X86::RDI, X86::RSI, X86::RCX, X86::R8, X86::R9, X86::R10, X86::R11};

// Registers that are clobbered by a syscall
static DenseSet<MCRegister> const SYSCALL_CLOBBERED_REGS{X86::RCX, X86::R11};

// Registers that are never used for any form of argument passing
static DenseSet<MCRegister> const NON_ARGUMENT_REGS{
    X86::R11, X86::R12, X86::R13, X86::R14, X86::R15, X86::RBP, X86::RBX};

// Registers that are used for return values
static DenseSet<MCRegister> const RETVAL_REGS{X86::RAX, X86::RDX};

static bool reg_is_taint_checked(MCRegister const &reg,
                                 MCRegisterInfo const &MRI,
                                 DenseSet<MCRegister> const &excluded) {
  static DenseSet<MCRegister> const TAINT_CHECKED_REGISTERS{
      X86::RAX, X86::RBX, X86::RCX, X86::RDX, X86::RDI,
      X86::RSI, X86::R8,  X86::R9,  X86::R10, X86::R11,
      X86::R12, X86::R13, X86::R14, X86::R15, X86::RBP};

  for (auto const &clean_reg : excluded) {
    if (MRI.isSubRegisterEq(clean_reg, reg)) {
      return false;
    }
  }

  for (auto const &checked_reg : TAINT_CHECKED_REGISTERS) {
    if (MRI.isSubRegisterEq(checked_reg, reg)) {
      return true;
    }
  }
  return false;
}

static DenseSet<MCRegister> get_tainted_registers(MCInst const &inst) {
  // The registers that are tainted as a result of this instruction.
  unsigned const opcode = inst.getOpcode();
  DenseSet<MCRegister> result;
  if (opcode == X86::SYSCALL) {
    result = SYSCALL_CLOBBERED_REGS;
  } else if (CALL_OPCODES.contains(opcode)) {
    result = CALL_CLOBBERED_REGS;
  }
  return result;
}

static DenseSet<MCRegister> get_written_registers(MCInst const &inst,
                                                  MCInstrDesc const &MID,
                                                  MCRegisterInfo const &MRI) {
  DenseSet<MCRegister> result;
  for (unsigned i = 0; i < MID.getNumDefs(); i++) {
    auto const &op = inst.getOperand(i);
    if (op.isReg() && op.getReg().isPhysical()) {
      MCRegister reg = op.getReg();
      if (get_register_size(reg, MRI) == 32) {
        // On x86-64, 32-bit writes are zero-extended
        for (auto const &superreg : MRI.superregs(reg)) {
          if (get_register_size(superreg, MRI) == 64) {
            reg = superreg;
            break;
          }
        }
      }
      result.insert(reg);
    }
  }

  if (inst.getOpcode() == X86::SYSCALL) {
    result.insert(X86::RAX);
  }

  auto const &implicit_defs = MID.implicit_defs();
  result.insert(implicit_defs.begin(), implicit_defs.end());
  return deduplicate_subregisters(result, MRI);
}

static DenseSet<MCRegister> get_uncleaned_registers(MCInst const &inst,
                                                    MCInstrDesc const &MID,
                                                    MCRegisterInfo const &MRI) {
  static DenseSet<unsigned> const POP_OPCODES{
      X86::POP16r,   X86::POP16rmm, X86::POP2,     X86::POP2P,   X86::POP32r,
      X86::POP32rmm, X86::POP64r,   X86::POP64rmm, X86::POPA16,  X86::POPA32,
      X86::POPDS16,  X86::POPDS32,  X86::POPES16,  X86::POPES32, X86::POPF16,
      X86::POPF32,   X86::POPF64,   X86::POPFS16,  X86::POPFS32, X86::POPFS64,
      X86::POPGS16,  X86::POPGS32,  X86::POPGS64,  X86::POPP64r, X86::POPSS16,
      X86::POPSS32,
  };

  DenseSet<MCRegister> result(get_tainted_registers(inst));
  if (POP_OPCODES.contains(inst.getOpcode())) {
    for (auto const &pop_operand : get_written_registers(inst, MID, MRI)) {
      if (reg_is_taint_checked(pop_operand, MRI, {})) {
        result.insert(pop_operand);
      }
    }
  }
  return result;
}

static DenseSet<MCRegister> get_cleaned_registers(MCInst const &inst,
                                                  MCInstrDesc const &MID,
                                                  MCRegisterInfo const &MRI) {
  // The registers that are cleaned as a result of this instruction.

  DenseSet<MCRegister> result;
  for (auto const &reg : get_written_registers(inst, MID, MRI)) {
    if (reg_is_taint_checked(reg, MRI, {})) {
      result.insert(reg);
    }
  }

  for (auto const &uncleaned_reg : get_uncleaned_registers(inst, MID, MRI)) {
    result.erase(uncleaned_reg);
  }

  return result;
}

static DenseSet<MCRegister> get_undirtied_registers(MCInst const &inst,
                                                    MCInstrDesc const &MID,
                                                    MCRegisterInfo const &MRI) {
  // The registers that are untainted as a result of this instruction.
  // Note that this is not the same as being cleaned; it just means if
  // we were previously certain that this register is dirty, we aren't
  // any longer after this instruction.
  unsigned const opcode = inst.getOpcode();
  DenseSet<MCRegister> result = get_cleaned_registers(inst, MID, MRI);
  if (CALL_OPCODES.contains(opcode)) {
    for (auto const &reg : RETVAL_REGS) {
      auto subregs = MRI.subregs_inclusive(reg);
      result.insert(subregs.begin(), subregs.end());
    }
  }
  return result;
}

static DenseSet<MCRegister> get_dirtied_registers(MCInst const &inst,
                                                  MCRegisterInfo const &MRI) {
  // The registers that are dirtied as a result of this instruction.
  DenseSet<MCRegister> result;
  for (auto const &reg : get_tainted_registers(inst)) {
    auto subregs = MRI.subregs_inclusive(reg);
    result.insert(subregs.begin(), subregs.end());
  }
  return result;
}

static DenseSet<MCRegister>
get_required_clean_registers(MCInst const &inst, MCInstrDesc const &MID,
                             MCRegisterInfo const &MRI) {
  static DenseSet<unsigned> const PUSH_OPCODES{
      X86::PUSH16i,   X86::PUSH16i8, X86::PUSH16r,   X86::PUSH16rmm,
      X86::PUSH16rmr, X86::PUSH2,    X86::PUSH2P,    X86::PUSH32i,
      X86::PUSH32i8,  X86::PUSH32r,  X86::PUSH32rmm, X86::PUSH32rmr,
      X86::PUSH64i32, X86::PUSH64i8, X86::PUSH64r,   X86::PUSH64rmm,
      X86::PUSH64rmr, X86::PUSHA16,  X86::PUSHA32,   X86::PUSHCS16,
      X86::PUSHCS32,  X86::PUSHDS16, X86::PUSHDS32,  X86::PUSHES16,
      X86::PUSHES32,  X86::PUSHF16,  X86::PUSHF32,   X86::PUSHF64,
      X86::PUSHFS16,  X86::PUSHFS32, X86::PUSHFS64,  X86::PUSHGS16,
      X86::PUSHGS32,  X86::PUSHGS64, X86::PUSHP64r,  X86::PUSHSS16,
      X86::PUSHSS32};

  static DenseSet<unsigned> const XOR_RR_OPCODES{
      X86::XOR8rr,
      X86::XOR16rr,
      X86::XOR32rr,
      X86::XOR64rr,
  };
  unsigned const opcode = inst.getOpcode();
  if (XOR_RR_OPCODES.contains(opcode) &&
      get_required_clean_registers(inst, MID, MRI).size() == 1) {
    // xor $x, $x
    return {};
  }
  if (PUSH_OPCODES.contains(opcode)) {
    // push is used for saving registers, so it's allowed to access dirty or
    // tainted registers
    return {};
  }

  // Returns the registers that must be clean for this instruction to execute.
  DenseSet<MCRegister> read_registers;
  for (unsigned i = MID.getNumDefs(); i < MID.getNumOperands(); i++) {
    auto const &op = inst.getOperand(i);
    if (op.isReg() && op.getReg().isPhysical()) {
      read_registers.insert(op.getReg());
    }
  }

  auto const &implicit_uses = MID.implicit_uses();
  read_registers.insert(implicit_uses.begin(), implicit_uses.end());
  if (inst.getOpcode() == X86::SYSCALL) {
    read_registers.insert(X86::EAX);
    // TODO: Check the syscall number and check more args conditionally
  }

  DenseSet<MCRegister> result;
  for (auto const &reg : read_registers) {
    if (reg_is_taint_checked(reg, MRI, {})) {
      result.insert(reg);
    }
  }

  return deduplicate_subregisters(result, MRI);
}

static uint8_t get_taint_check_mask(MCRegister const &reg,
                                    MCRegisterInfo const &MRI) {
  switch (get_register_size(reg, MRI)) {
  case 8:
    switch (reg) {
    case X86::AH:
    case X86::BH:
    case X86::CH:
    case X86::DH:
      return 0b10;
    }
    return 0b1;
  case 16:
    return 0b11;
  case 32:
    return 0xf;
  case 64:
    return 0xff;
  }
  errs() << "Invalid register passed to get_taint_mask.\n";
  exit(1);
}

static uint8_t get_taint_clear_mask(MCRegister const &reg,
                                    MCRegisterInfo const &MRI) {
  return ~get_taint_check_mask(reg, MRI);
}

static uint8_t get_taint_state_index(MCRegister const &reg,
                                     MCRegisterInfo const &MRI) {
  MCRegister main_register = reg;
  if (get_register_size(reg, MRI) != 64) {
    bool found = false;
    for (auto const &superreg : MRI.superregs(reg)) {
      if (get_register_size(superreg, MRI) == 64) {
        found = true;
        main_register = superreg;
        break;
      }
    }
    if (!found) {
      errs() << "Couldn't find superreg for " << MRI.getName(reg)
             << " in get_taint_state_index!\n";
      exit(1);
    }
  }
  switch (main_register) {
  case X86::RAX:
    return TAINT_STATE_RAX;
  case X86::RBX:
    return TAINT_STATE_RBX;
  case X86::RCX:
    return TAINT_STATE_RCX;
  case X86::RDX:
    return TAINT_STATE_RDX;
  case X86::RDI:
    return TAINT_STATE_RDI;
  case X86::RSI:
    return TAINT_STATE_RSI;
  case X86::R8:
    return TAINT_STATE_R8;
  case X86::R9:
    return TAINT_STATE_R9;
  case X86::R10:
    return TAINT_STATE_R10;
  case X86::R11:
    return TAINT_STATE_R11;
  case X86::R12:
    return TAINT_STATE_R12;
  case X86::R13:
    return TAINT_STATE_R13;
  case X86::R14:
    return TAINT_STATE_R14;
  case X86::R15:
    return TAINT_STATE_R15;
  case X86::RBP:
    return TAINT_STATE_RBP;
  }

  errs() << "Superreg " << MRI.getName(main_register)
         << " found, but not taint-checked in get_taint_state_index!\n";
  exit(1);
}

static std::string get_fail_taint_symbol(MCRegister const &reg,
                                         MCRegisterInfo const &MRI) {
  std::string result("__abisan_fail_taint_");
  for (auto const &c : std::string(MRI.getName(reg))) {
    result.push_back(std::tolower(c));
  }
  return result;
}

class ABISanStreamer : public MCAsmStreamer {
  // Does the instrumentation :)

  MCInstrInfo const &MCII;
  MCSubtargetInfo const &STI;
  DenseSet<MCSymbol *> const &instrumented_symbols;
  DenseSet<MCRegister> clean; // Registers statically known to be clean. If X is
                              // clean, it is implied that X's subregs are too.
  DenseSet<MCRegister> dirty; // Registers statically known to be dirty. If X is
                              // dirty, it is possible that X's subregs are not.

  void deduplicate_clean() {
    clean = deduplicate_subregisters(clean, *getContext().getRegisterInfo());
  }

  void emit_instructions(std::vector<MCInst> insts) {
    for (auto const &i : insts) {
      MCAsmStreamer::emitInstruction(i, STI);
    }
  }

  void emit_entry_call() {
    MCContext &Ctx = getContext();
    emit_instructions(
        {MCInstBuilder(X86::CALL64pcrel32)
             .addExpr(MCSymbolRefExpr::create(
                 Ctx.getOrCreateSymbol("__abisan_function_entry"), Ctx))});
  }

  void emit_taint_check_prologue() {
    emit_instructions({
        // push rbp
        MCInstBuilder(X86::PUSH64r).addReg(X86::RBP),
        // mov rbp, rsp
        MCInstBuilder(X86::MOV64rr).addReg(X86::RBP).addReg(X86::RSP),
        // and rsp, 0xfffffffffffffff0
        MCInstBuilder(X86::AND64ri8)
            .addReg(X86::RSP)
            .addReg(X86::RSP)
            .addImm(0xfffffffffffffff0ull),
        // push rax
        MCInstBuilder(X86::PUSH64r).addReg(X86::RAX),
    });
  }

  void emit_taint_check(MCRegister const &reg) {
    MCContext &Ctx = getContext();
    MCRegisterInfo const &MRI = *Ctx.getRegisterInfo();
    uint8_t const taint_check_mask = get_taint_check_mask(reg, MRI);
    if (taint_check_mask == 0xff) {
      emit_instructions({
          // cmp byte ptr [rip + __abisan_taint_state +
          // TAINT_STATE_$REG], 0
          MCInstBuilder(X86::CMP8mi)
              .addReg(X86::RIP)
              .addImm(1 /* scale */)
              .addReg(0 /* index */)
              .addExpr(MCBinaryExpr::createAdd(
                  MCSymbolRefExpr::create(
                      Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                  MCConstantExpr::create(get_taint_state_index(reg, MRI), Ctx),
                  Ctx))
              .addReg(0 /* segment register */)
              .addImm(0),
          // jne __abisan_fail_taint_$REG
          MCInstBuilder(X86::JCC_1)
              .addExpr(MCSymbolRefExpr::create(
                  Ctx.getOrCreateSymbol(get_fail_taint_symbol(reg, MRI)), Ctx))
              .addImm(X86::COND_NE),
      });
    } else {
      emit_instructions({
          // mov al, byte ptr [rip + __abisan_taint_state +
          // TAINT_STATE_$REG]
          MCInstBuilder(X86::MOV8rm)
              .addReg(X86::AL)
              .addReg(X86::RIP)
              .addImm(1 /* scale */)
              .addReg(0 /* index */)
              .addExpr(MCBinaryExpr::createAdd(
                  MCSymbolRefExpr::create(
                      Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                  MCConstantExpr::create(get_taint_state_index(reg, MRI), Ctx),
                  Ctx))
              .addReg(0 /* segment register */),
          // and al, TAINT_MASK($REG)
          MCInstBuilder(X86::AND8ri)
              .addReg(X86::AL)
              .addReg(X86::AL)
              .addImm(taint_check_mask),
          // cmp al, 0
          MCInstBuilder(X86::CMP8ri).addReg(X86::AL).addImm(0),
          // jne __abisan_fail_taint_$REG
          MCInstBuilder(X86::JCC_1)
              .addExpr(MCSymbolRefExpr::create(
                  Ctx.getOrCreateSymbol(get_fail_taint_symbol(reg, MRI)), Ctx))
              .addImm(X86::COND_NE),
      });
    }
  }

  void emit_taint_check_epilogue() {
    emit_instructions({
        // pop rax
        MCInstBuilder(X86::POP64r).addReg(X86::RAX),
        // leave
        MCInstBuilder(X86::LEAVE),
    });
  }

  void emit_taint_clear(MCRegister const &reg) {
    MCContext &Ctx = getContext();
    MCRegisterInfo const &MRI = *Ctx.getRegisterInfo();

    emit_instructions(
        {// and byte ptr [rip + __abisan_taint_state + TAINT_STATE_$REG],
         // ~TAINT_MASK($REG)
         MCInstBuilder(X86::AND8mi)
             .addReg(X86::RIP)
             .addImm(1 /* scale */)
             .addReg(0 /* index */)
             .addExpr(MCBinaryExpr::createAdd(
                 MCSymbolRefExpr::create(
                     Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                 MCConstantExpr::create(get_taint_state_index(reg, MRI), Ctx),
                 Ctx))
             .addReg(0 /* segment register */)
             .addImm(get_taint_clear_mask(reg, MRI))});
  }

  void emit_taint_prologue() {
    emit_instructions({
        // pushfq
        MCInstBuilder(X86::PUSHF64),
    });
  }

  void emit_taint_epilogue() {
    emit_instructions({MCInstBuilder(X86::POPF64)});
  }

  void emit_taint_set(MCRegister const &reg) {
    MCContext &Ctx = getContext();
    MCRegisterInfo const &MRI = *Ctx.getRegisterInfo();
    emit_instructions(
        {MCInstBuilder(X86::MOV8mi)
             .addReg(X86::RIP)
             .addImm(1 /* scale */)
             .addReg(0 /* index */)
             .addExpr(MCBinaryExpr::createAdd(
                 MCSymbolRefExpr::create(
                     Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                 MCConstantExpr::create(get_taint_state_index(reg, MRI), Ctx),
                 Ctx))
             .addReg(0 /* segment register */)
             .addImm(0xff)});
  }

public:
  ABISanStreamer(MCContext &Context, std::unique_ptr<formatted_raw_ostream> os,
                 std::unique_ptr<MCInstPrinter> printer,
                 std::unique_ptr<MCCodeEmitter> emitter,
                 std::unique_ptr<MCAsmBackend> asmbackend,
                 MCInstrInfo const &mcii, MCSubtargetInfo const &sti,
                 DenseSet<MCSymbol *> const &symbols_to_instrument)
      : MCAsmStreamer(Context, std::move(os), std::move(printer),
                      std::move(emitter), std::move(asmbackend)),
        MCII(mcii), STI(sti), instrumented_symbols(symbols_to_instrument) {}

  void emitInstruction(MCInst const &inst, MCSubtargetInfo const &) override {
    MCContext &Ctx = getContext();
    MCRegisterInfo const &MRI = *Ctx.getRegisterInfo();
    MCInstrDesc const &MID = MCII.get(inst.getOpcode());

    bool have_emitted_instrumentation = false;
    for (auto const &reg : get_required_clean_registers(inst, MID, MRI)) {
      if (reg_is_taint_checked(reg, MRI, clean)) {
        // If this register is statically known to be dirty, issue a warning
        if (dirty.contains(reg)) {
          Ctx.reportWarning(getStartTokLoc(),
                            Twine("you will access a tainted ")
                                .concat(Twine(MRI.getName(reg)))
                                .concat(Twine(".")));
        }
        if (!have_emitted_instrumentation) {
          emit_taint_prologue();
          emit_taint_check_prologue();
          have_emitted_instrumentation = true;
        }

        emit_taint_check(reg);
      }
    }

    if (have_emitted_instrumentation) {
      emit_taint_check_epilogue();
    }

    for (auto const &reg : get_cleaned_registers(inst, MID, MRI)) {
      if (!have_emitted_instrumentation) {
        emit_taint_prologue();
        have_emitted_instrumentation = true;
      }

      emit_taint_clear(reg);
    }
    if (have_emitted_instrumentation) {
      emit_taint_epilogue();
    }

    emit_instructions({inst});

    // Remove the undirtied registers from dirty
    for (auto const &reg : get_undirtied_registers(inst, MID, MRI)) {
      dirty.erase(reg);
    }

    // Remove the uncleaned registers from clean
    for (auto const &reg : get_uncleaned_registers(inst, MID, MRI)) {
      emitRawComment(Twine("Uncleaning ").concat(MRI.getName(reg)));
      clean.erase(reg);
    }

    // Mark the cleaned registers as clean
    auto const &cleaned_regs = get_cleaned_registers(inst, MID, MRI);
    clean.insert(cleaned_regs.begin(), cleaned_regs.end());
    deduplicate_clean();

    // Mark the dirtied registers as dirty
    auto const &dirtied_regs = get_dirtied_registers(inst, MRI);
    dirty.insert(dirtied_regs.begin(), dirtied_regs.end());

    // Emit taint instructions for each tainted register
    // This needs to happen after the instruction is emitted because it won't
    // work for call otherwise.
    for (auto const &tainted_reg : get_tainted_registers(inst)) {
      if (get_taint_clear_mask(tainted_reg, MRI) != 0) {
        errs() << "All tainted registers must be full width. This should never "
                  "happen.\n";
        exit(1);
      }
      emit_taint_set(tainted_reg);
    }

    // If the instruction is a ret, and any nonvolatile register is clean, issue
    // a warning
    if (RET_OPCODES.contains(inst.getOpcode())) {
      for (auto const &clean_reg : clean) {
        for (auto const &nv_reg : NONVOLATILE_REGS) {
          if (MRI.isSubRegisterEq(nv_reg, clean_reg)) {
            Ctx.reportWarning(getStartTokLoc(),
                              Twine("you will clobber ")
                                  .concat(Twine(MRI.getName(nv_reg)))
                                  .concat(Twine(".")));
          }
        }
      }
    }
  }

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override {
    MCAsmStreamer::emitLabel(Symbol, Loc);
    // Because a label could be a jump target,
    // we need to clear the dirty and clean sets.
    clean.clear();
    dirty.clear();
    for (auto instrumented_symbol : instrumented_symbols) {
      if (Symbol->getName().str() == instrumented_symbol->getName().str()) {
        MCRegisterInfo const &MRI = *getContext().getRegisterInfo();
        // Mark the non-arg registers as dirty.
        // The corresponding tainting happens in __abisan_function_entry
        for (auto const &non_arg_reg : NON_ARGUMENT_REGS) {
          auto subregs = MRI.subregs_inclusive(non_arg_reg);
          dirty.insert(subregs.begin(), subregs.end());
        }
        // No need to deduplicate here because we know that the dirty set was
        // empty. Unless any of the non_arg_regs overlap? This isn't a thing on
        // x86, at least.

        // We can't add the arg registers to clean, because we don't know if
        // they'll be used.

        // call __abisan_function_entry
        emit_entry_call();
        return;
      }
    }
  }
};

static std::unique_ptr<SourceMgr> make_sm(char const *const filename) {
  std::unique_ptr<SourceMgr> SM = std::make_unique<SourceMgr>();
  auto buffer_or_error = MemoryBuffer::getFile(filename);
  if (!buffer_or_error) {
    errs() << "Error reading file: " << filename << "\n";
    exit(1);
  }

  SM->AddNewSourceBuffer(std::move(*buffer_or_error), SMLoc());
  return SM;
}

static std::unique_ptr<MCObjectFileInfo const> make_mofi(MCContext &Ctx) {
  std::unique_ptr<MCObjectFileInfo> MOFI = std::make_unique<MCObjectFileInfo>();
  MOFI->initMCObjectFileInfo(Ctx, false);
  return MOFI;
}

int main(int const argc, char const *const *const argv) {
  if (argc < 2) {
    errs() << "Usage: " << argv[0] << " <file.s>\n";
    exit(1);
  }

  InitializeAllTargetInfos();
  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();
  InitializeAllAsmParsers();

  std::string error;
  std::string triple_name = sys::getDefaultTargetTriple();
  Triple const triple = Triple(triple_name);
  Target const *const Target = TargetRegistry::lookupTarget(triple_name, error);

  if (!Target) {
    errs() << "Failed to lookup target: " << error << "\n";
    exit(1);
  }

  MCTargetOptions const options;
  std::shared_ptr<MCRegisterInfo const> MRI(Target->createMCRegInfo(triple));
  std::shared_ptr<MCAsmInfo const> MAI(
      Target->createMCAsmInfo(*MRI, triple, options));
  std::shared_ptr<MCSubtargetInfo const> STI(
      Target->createMCSubtargetInfo(triple, "", ""));
  std::shared_ptr<MCInstrInfo const> MCII(Target->createMCInstrInfo());

  std::unique_ptr<SourceMgr> const SM =
      make_sm(argv[1]); // Lifetime bound to FPCtx and Ctx
  MCContext FPCtx(triple, MAI.get(), MRI.get(), STI.get(), SM.get());
  std::unique_ptr<MCObjectFileInfo const> FPMOFI =
      make_mofi(FPCtx); // Lifetime bound to FPCtx
  FPCtx.setObjectFileInfo(FPMOFI.get());

  // First pass starts here.
  // The point of the first pass is to locate all the symbols that need to be
  // instrumented.

  ABISanFirstPassStreamer FPStreamer(
      FPCtx, std::make_unique<formatted_raw_ostream>(nulls()),
      std::unique_ptr<MCInstPrinter>(Target->createMCInstPrinter(
          triple, MAI->getAssemblerDialect(), *MAI, *MCII, *MRI)),
      std::unique_ptr<MCCodeEmitter>(),
      std::unique_ptr<MCAsmBackend>(
          Target->createMCAsmBackend(*STI, *MRI, options)));

  std::unique_ptr<MCAsmParser> FPParser(
      createMCAsmParser(*SM.get(), FPCtx, FPStreamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> FPTargetParser(
      Target->createMCAsmParser(*STI, *FPParser, *MCII, options));
  if (!FPTargetParser) {
    errs() << "No target-specific asm parser for triple!\n";
    exit(1);
  }
  FPParser->setTargetParser(*FPTargetParser);
  if (FPParser->Run(false)) {
    errs() << "Failed to parse assembly.\n";
    exit(1);
  }

  // Second pass starts here.
  // This is where the instrumentation actually happens.

  MCContext Ctx(triple, MAI.get(), MRI.get(), STI.get(), SM.get());
  std::unique_ptr<MCObjectFileInfo const> MOFI =
      make_mofi(Ctx); // Lifetime bound to Ctx
  Ctx.setObjectFileInfo(MOFI.get());

  ABISanStreamer Streamer(
      Ctx, std::make_unique<formatted_raw_ostream>(outs()),
      std::unique_ptr<MCInstPrinter>(Target->createMCInstPrinter(
          triple, MAI->getAssemblerDialect(), *MAI, *MCII, *MRI)),
      std::unique_ptr<MCCodeEmitter>(),
      std::unique_ptr<MCAsmBackend>(
          Target->createMCAsmBackend(*STI, *MRI, options)),
      *MCII, *STI, FPStreamer.instrumented_symbols);
  Streamer.initSections(false, *STI);

  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(*SM.get(), Ctx, Streamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> TargetParser(
      Target->createMCAsmParser(*STI, *Parser, *MCII, options));
  if (!TargetParser) {
    errs() << "No target-specific asm parser for triple!\n";
    exit(1);
  }
  Parser->setTargetParser(*TargetParser);
  if (Parser->Run(false)) {
    errs() << "Failed to parse assembly.\n";
    exit(1);
  }
}
