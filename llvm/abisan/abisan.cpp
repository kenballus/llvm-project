#include "Target/X86/MCTargetDesc/X86BaseInfo.h"
#include "Target/X86/MCTargetDesc/X86MCTargetDesc.h"
#include "Target/X86/X86.h"
#include "Target/X86/X86RegisterInfo.h"
#include "X86InstrInfo.h"
#include "abisan_runtime.h"
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
#include <algorithm> // for std::find
#include <cctype>    // for std::tolower
#include <unordered_set>
#include <vector>

using namespace llvm;

class ABISanFirstPassStreamer : public MCAsmStreamer {
  // This class exists to make a first pass over the .s file to collect
  // all the names of the functions we want to instrument.
public:
  std::unordered_set<std::string> instrumented_symbol_names;
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
      instrumented_symbol_names.insert(Symbol->getName().str());
    }
    return result;
  }
};

static std::vector<MCRegister>
deduplicate_registers(std::vector<MCRegister> const &regs,
                      MCRegisterInfo const &MRI) {
  std::vector<MCRegister> deduped_regs;
  for (auto const &reg : regs) {
    bool is_dup = false;
    for (auto const &dedup_reg : deduped_regs) {
      if (dedup_reg == reg) {
        is_dup = true;
        break;
      }
    }
    if (!is_dup) {
      deduped_regs.push_back(reg);
    }
  }

  std::vector<MCRegister> result;
  for (auto const &r1 : deduped_regs) {
    bool is_sub = false;
    for (auto const &r2 : deduped_regs) {
      if (MRI.isSubRegister(r2, r1)) {
        is_sub = true;
        break;
      }
    }
    if (!is_sub) {
      result.push_back(r1);
    }
  }

  return result;
}

static std::unordered_set<unsigned> const CALL_OPCODES{
    X86::CALL16r, X86::CALL16m, X86::CALLpcrel16,
    X86::CALL32r, X86::CALL32m, X86::CALLpcrel32,
    X86::CALL64r, X86::CALL64m, X86::CALL64pcrel32,
};

static std::vector<MCRegister>
get_written_registers(MCInst const &inst, MCInstrDesc const &MID,
                      MCRegisterInfo const &MRI) {
  std::vector<MCRegister> result;
  for (unsigned i = 0; i < MRI.getNumRegs(); i++) {
    if (MID.hasDefOfPhysReg(inst, MCRegister::from(i), MRI)) {
      result.push_back(MCRegister::from(i));
    }
  }

  unsigned const opcode = inst.getOpcode();
  if (opcode == X86::SYSCALL) {
    result.insert(result.end(), {X86::RCX, X86::R11, X86::RAX});
  } else if (CALL_OPCODES.find(opcode) != CALL_OPCODES.end()) {
    result.insert(
        result.end(),
        {X86::RAX,
         X86::RDX}); // TODO: only do this depending on what the fn returns
  }

  return deduplicate_registers(result, MRI);
}

static std::vector<MCRegister> get_read_registers(MCInst const &inst,
                                                  MCInstrDesc const &MID,
                                                  MCRegisterInfo const &MRI) {
  std::vector<MCRegister> result;
  for (unsigned i = MID.getNumDefs(); i < MID.getNumOperands(); i++) {
    auto const &op = inst.getOperand(i);
    if (op.isReg() && op.getReg().isPhysical()) {
      result.push_back(op.getReg());
    }
  }

  // TODO: handle variadic operands

  auto const &implicit_uses = MID.implicit_uses();
  result.insert(result.end(), implicit_uses.begin(), implicit_uses.end());
  if (inst.getOpcode() == X86::SYSCALL) {
    result.push_back(X86::RAX);
  }

  return deduplicate_registers(result, MRI);
}

static bool reg_is_taint_checked(MCRegister const &reg,
                                 MCRegisterInfo const &MRI,
                                 std::vector<MCRegister> const &excluded) {
  static std::vector<MCRegister> const TAINT_CHECKED_REGISTERS{
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

static bool inst_is_taint_checked(MCInst const &inst, MCInstrDesc const &MID,
                                  MCRegisterInfo const &MRI) {
  static std::unordered_set<unsigned> const TAINT_UNCHECKED_OPCODES{
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

  static std::unordered_set<unsigned> const XOR_RR_OPCODES{
      X86::XOR8rr,
      X86::XOR16rr,
      X86::XOR32rr,
      X86::XOR64rr,
  };
  unsigned const opcode = inst.getOpcode();
  if (XOR_RR_OPCODES.find(opcode) != XOR_RR_OPCODES.end() &&
      get_read_registers(inst, MID, MRI).size() == 1) {
    // xor $x, $x
    return false;
  }

  return TAINT_UNCHECKED_OPCODES.find(opcode) == TAINT_UNCHECKED_OPCODES.end();
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
    outs() << "Unable to find register class for " << MRI.getName(reg) << "!\n";
    exit(1);
  }
  return result;
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
      return 0b00000010;
    }
    return 0b00000001;
  case 16:
    return 0b00000011;
  case 32:
    return 0b00001111;
  case 64:
    return 0b11111111;
  }
  outs() << "Invalid register passed to get_taint_mask.\n";
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
      outs() << "Couldn't find superreg for " << MRI.getName(reg)
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

  outs() << "Superreg found, but not taint-checked in get_taint_state_index!\n";
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

#define CALL_CLOBBERED_REGS                                                    \
  X86::RDI, X86::RSI, X86::RCX, X86::R8, X86::R9, X86::R10, X86::R11

class ABISanStreamer : public MCAsmStreamer {
  // Does the instrumentation :)

  MCInstrInfo const &MCII;
  MCSubtargetInfo const &STI;
  std::unordered_set<std::string> const &instrumented_symbol_names;
  std::vector<MCRegister> clean_registers;
  std::vector<MCRegister> dirty_registers;

public:
  ABISanStreamer(MCContext &Context, std::unique_ptr<formatted_raw_ostream> os,
                 std::unique_ptr<MCInstPrinter> printer,
                 std::unique_ptr<MCCodeEmitter> emitter,
                 std::unique_ptr<MCAsmBackend> asmbackend,
                 MCInstrInfo const &mcii, MCSubtargetInfo const &sti,
                 std::unordered_set<std::string> const &gsn)
      : MCAsmStreamer(Context, std::move(os), std::move(printer),
                      std::move(emitter), std::move(asmbackend)),
        MCII(mcii), STI(sti), instrumented_symbol_names(gsn) {}

  void emitInstruction(MCInst const &inst,
                       MCSubtargetInfo const &STIArg) override {
    MCContext &Ctx = getContext();
    MCRegisterInfo const &MRI = *Ctx.getRegisterInfo();
    MCInstrDesc const &MID = MCII.get(inst.getOpcode());

    bool have_affected_flags = false;
    std::vector<MCInst> insts;
    for (auto const &reg : get_read_registers(inst, MID, MRI)) {
      if (inst_is_taint_checked(inst, MID, MRI) &&
          reg_is_taint_checked(reg, MRI, clean_registers)) {
        if (std::find(dirty_registers.begin(), dirty_registers.end(), reg) !=
            dirty_registers.end()) {
          errs() << "\x1b[0;31mABISanitizer warning: access to tainted "
                 << MRI.getName(reg) << "\x1b[0m";
        }
        if (!have_affected_flags) {
          insts.insert(
              insts.end(),
              {
                  // pushfq
                  MCInstBuilder(X86::PUSHF64),
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
          have_affected_flags = true;
        }

        uint8_t const taint_check_mask = get_taint_check_mask(reg, MRI);
        if (taint_check_mask == 0b11111111) {
          insts.insert(
              insts.end(),
              {
                  // cmp byte ptr [rip + __abisan_taint_state +
                  // TAINT_STATE_$REG], 0
                  MCInstBuilder(X86::CMP8mi)
                      .addReg(X86::RIP)
                      .addImm(1 /* scale */)
                      .addReg(0 /* index */)
                      .addExpr(MCBinaryExpr::createAdd(
                          MCSymbolRefExpr::create(
                              Ctx.getOrCreateSymbol("__abisan_taint_state"),
                              Ctx),
                          MCConstantExpr::create(
                              get_taint_state_index(reg, MRI), Ctx),
                          Ctx))
                      .addReg(0 /* segment register */)
                      .addImm(0),
                  // jne __abisan_fail_taint_$REG
                  MCInstBuilder(X86::JCC_1)
                      .addExpr(MCSymbolRefExpr::create(
                          Ctx.getOrCreateSymbol(
                              get_fail_taint_symbol(reg, MRI)),
                          Ctx))
                      .addImm(X86::COND_NE),
              });
        } else {
          insts.insert(
              insts.end(),
              {
                  // mov al, byte ptr [rip + __abisan_taint_state +
                  // TAINT_STATE_$REG]
                  MCInstBuilder(X86::MOV8rm)
                      .addReg(X86::AL)
                      .addReg(X86::RIP)
                      .addImm(1 /* scale */)
                      .addReg(0 /* index */)
                      .addExpr(MCBinaryExpr::createAdd(
                          MCSymbolRefExpr::create(
                              Ctx.getOrCreateSymbol("__abisan_taint_state"),
                              Ctx),
                          MCConstantExpr::create(
                              get_taint_state_index(reg, MRI), Ctx),
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
                          Ctx.getOrCreateSymbol(
                              get_fail_taint_symbol(reg, MRI)),
                          Ctx))
                      .addImm(X86::COND_NE),
              });
        }
      }
    }

    if (have_affected_flags) {
      insts.insert(insts.end(), {
                                    // pop rax
                                    MCInstBuilder(X86::POP64r).addReg(X86::RAX),
                                    // leave
                                    MCInstBuilder(X86::LEAVE),
                                });
    }

    for (auto const &reg : get_written_registers(inst, MID, MRI)) {
      if (reg_is_taint_checked(reg, MRI, {})) {
        uint8_t taint_clear_mask = get_taint_clear_mask(reg, MRI);

        if (!have_affected_flags && taint_clear_mask != 0) {
          insts.push_back(MCInstBuilder(X86::PUSHF64));
          have_affected_flags = true;
        }

        if (taint_clear_mask == 0) {
          insts.insert(
              insts.end(),
              {// mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_$REG],
               // 0
               MCInstBuilder(X86::MOV8mi)
                   .addReg(X86::RIP)
                   .addImm(1 /* scale */)
                   .addReg(0 /* index */)
                   .addExpr(MCBinaryExpr::createAdd(
                       MCSymbolRefExpr::create(
                           Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                       MCConstantExpr::create(get_taint_state_index(reg, MRI),
                                              Ctx),
                       Ctx))
                   .addReg(0 /* segment register */)
                   .addImm(0)});
        } else {
          insts.insert(
              insts.end(),
              {// and byte ptr [rip + __abisan_taint_state + TAINT_STATE_$REG],
               // ~TAINT_MASK($REG)
               MCInstBuilder(X86::AND8mi)
                   .addReg(X86::RIP)
                   .addImm(1 /* scale */)
                   .addReg(0 /* index */)
                   .addExpr(MCBinaryExpr::createAdd(
                       MCSymbolRefExpr::create(
                           Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                       MCConstantExpr::create(get_taint_state_index(reg, MRI),
                                              Ctx),
                       Ctx))
                   .addReg(0 /* segment register */)
                   .addImm(get_taint_clear_mask(reg, MRI))});
        }
        clean_registers.push_back(reg);
        for (auto it = dirty_registers.begin(); it != dirty_registers.end();
             it++) {
          if (MRI.isSubRegisterEq(reg, *it)) {
            dirty_registers.erase(it);
            break;
          }
        }
      }
    }

    if (have_affected_flags) {
      insts.push_back(MCInstBuilder(X86::POPF64));
    }
    insts.push_back(inst);
    if (std::find(CALL_OPCODES.begin(), CALL_OPCODES.end(), inst.getOpcode()) !=
        CALL_OPCODES.end()) {
      for (auto const &reg : {CALL_CLOBBERED_REGS}) {
        insts.push_back(
            MCInstBuilder(X86::MOV8mi)
                .addReg(X86::RIP)
                .addImm(1 /* scale */)
                .addReg(0 /* index */)
                .addExpr(MCBinaryExpr::createAdd(
                    MCSymbolRefExpr::create(
                        Ctx.getOrCreateSymbol("__abisan_taint_state"), Ctx),
                    MCConstantExpr::create(get_taint_state_index(reg, MRI),
                                           Ctx),
                    Ctx))
                .addReg(0 /* segment register */)
                .addImm(0b11111111));
      }
      dirty_registers.clear();
      dirty_registers.insert(dirty_registers.end(), {CALL_CLOBBERED_REGS});
    }
    for (auto const &i : insts) {
      MCAsmStreamer::emitInstruction(i, STIArg);
    }
    if (MID.mayAffectControlFlow(inst, MRI)) {
      clean_registers.clear();
    }
  }

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override {
    clean_registers.clear();
    dirty_registers.clear();
    dirty_registers.insert(dirty_registers.begin(), {X86::R11});
    MCAsmStreamer::emitLabel(Symbol, Loc);
    for (auto const &instrumented_symbol_name : instrumented_symbol_names) {
      if (Symbol->getName().str() == instrumented_symbol_name) {
        MCAsmStreamer::emitInstruction(
            MCInstBuilder(X86::CALL64pcrel32)
                .addExpr(MCSymbolRefExpr::create(
                    getContext().getOrCreateSymbol("__abisan_function_entry"),
                    getContext())),
            STI);
      }
    }
  }
};

static std::unique_ptr<SourceMgr> make_sm(char const *const filename) {
  std::unique_ptr<SourceMgr> SM = std::make_unique<SourceMgr>();
  auto buffer_or_error = MemoryBuffer::getFile(filename);
  if (!buffer_or_error) {
    outs() << "Error reading file: " << filename << "\n";
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
    outs() << "Usage: " << argv[0] << " <file.s>\n";
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
    outs() << "Failed to lookup target: " << error << "\n";
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
      make_sm(argv[1]); // Lifetime bound to Ctx
  MCContext Ctx(triple, MAI.get(), MRI.get(), STI.get(), SM.get());
  std::unique_ptr<MCObjectFileInfo const> MOFI =
      make_mofi(Ctx); // Lifetime bound to Ctx
  Ctx.setObjectFileInfo(MOFI.get());

  ABISanFirstPassStreamer FPStreamer(
      Ctx, std::make_unique<formatted_raw_ostream>(nulls()),
      std::unique_ptr<MCInstPrinter>(Target->createMCInstPrinter(
          triple, MAI->getAssemblerDialect(), *MAI, *MCII, *MRI)),
      std::unique_ptr<MCCodeEmitter>(),
      std::unique_ptr<MCAsmBackend>(
          Target->createMCAsmBackend(*STI, *MRI, options)));

  std::unique_ptr<MCAsmParser> FPParser(
      createMCAsmParser(*SM.get(), Ctx, FPStreamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> FPTargetParser(
      Target->createMCAsmParser(*STI, *FPParser, *MCII, options));
  if (!FPTargetParser) {
    outs() << "No target-specific asm parser for triple!\n";
    exit(1);
  }
  FPParser->setTargetParser(*FPTargetParser);
  if (FPParser->Run(false)) {
    outs() << "Failed to parse assembly.\n";
    exit(1);
  }

  Ctx.reset();

  // Second pass starts here

  ABISanStreamer Streamer(
      Ctx, std::make_unique<formatted_raw_ostream>(outs()),
      std::unique_ptr<MCInstPrinter>(Target->createMCInstPrinter(
          triple, MAI->getAssemblerDialect(), *MAI, *MCII, *MRI)),
      std::unique_ptr<MCCodeEmitter>(),
      std::unique_ptr<MCAsmBackend>(
          Target->createMCAsmBackend(*STI, *MRI, options)),
      *MCII, *STI, FPStreamer.instrumented_symbol_names);
  Streamer.initSections(false, *STI);

  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(*SM.get(), Ctx, Streamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> TargetParser(
      Target->createMCAsmParser(*STI, *Parser, *MCII, options));
  if (!TargetParser) {
    outs() << "No target-specific asm parser for triple!\n";
    exit(1);
  }
  Parser->setTargetParser(*TargetParser);
  if (Parser->Run(false)) {
    outs() << "Failed to parse assembly.\n";
    exit(1);
  }
}
