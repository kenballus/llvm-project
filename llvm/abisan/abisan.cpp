#include "Target/X86/MCTargetDesc/X86BaseInfo.h"
#include "Target/X86/MCTargetDesc/X86MCTargetDesc.h"
#include "Target/X86/X86.h"
#include "Target/X86/X86RegisterInfo.h"
#include "X86GenInstrInfo.inc"
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
#include <unordered_set>
#include <vector>

using namespace llvm;

class ABISanFirstPassStreamer : public MCAsmStreamer {
  // This class exists to make a first pass over the .s file to collect
  // all the names of the functions we want to instrument.
public:
  std::unordered_set<std::string> global_symbol_names;
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
        (!Symbol->isInSection() ||
         Symbol->getSection()
             .hasInstructions())) { // .globl and has code and is in an
                                    // executable section, or no section
      global_symbol_names.insert(Symbol->getName().str());
    }
    return result;
  }
};

static std::vector<MCRegister> get_written_registers(MCInst const &inst,
                                                     MCInstrInfo const &MCII) {
  MCInstrDesc const &instr_desc = MCII.get(inst.getOpcode());

  std::vector<MCRegister> result;
  for (unsigned i = 0; i < instr_desc.getNumDefs(); i++) {
    auto const &op = inst.getOperand(i);
    if (op.isReg() && op.getReg().isPhysical()) {
      result.push_back(op.getReg());
    }
  }

  auto const &implicit_defs = instr_desc.implicit_defs();
  result.insert(result.end(), implicit_defs.begin(), implicit_defs.end());
  if (inst.getOpcode() == X86::SYSCALL) {
    result.insert(result.end(), {X86::RCX, X86::R11, X86::RAX});
  }
  return result;
}

static std::vector<MCRegister> get_read_registers(MCInst const &inst,
                                                  MCInstrInfo const &MCII) {
  MCInstrDesc const &instr_desc = MCII.get(inst.getOpcode());

  std::vector<MCRegister> result;
  for (unsigned i = instr_desc.getNumDefs(); i < instr_desc.getNumOperands();
       i++) {
    auto const &op = inst.getOperand(i);
    if (op.isReg() && op.getReg().isPhysical()) {
      result.push_back(op.getReg());
    }
  }

  auto const &implicit_uses = instr_desc.implicit_uses();
  result.insert(result.end(), implicit_uses.begin(), implicit_uses.end());
  if (inst.getOpcode() == X86::SYSCALL) {
    result.insert(result.end(), {X86::RCX, X86::R11, X86::RAX});
  }
  return result;
}

static std::vector<MCRegister> const TAINT_CHECKED_REGISTERS{
    X86::RAX, X86::RBX, X86::RCX, X86::RDX,   X86::RDI, X86::RSI,
    X86::R8,  X86::R9,  X86::R10, X86::R11,   X86::R12, X86::R13,
    X86::R14, X86::R15, X86::RBP, X86::EFLAGS};

static bool is_taint_checked(MCRegister const &reg, MCRegisterInfo const &MRI) {
  for (auto const &checked_reg : TAINT_CHECKED_REGISTERS) {
    if (MRI.isSubRegisterEq(checked_reg, reg)) {
      return true;
    }
  }
  return false;
}

class ABISanStreamer : public MCAsmStreamer {
  // Does the instrumentation :)

  MCInstrInfo const &MCII;
  MCSubtargetInfo const &STI;
  std::unordered_set<std::string> const &instrumented_symbol_names;

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
    MCRegisterInfo const &MRI = *getContext().getRegisterInfo();

    for (auto const &reg : get_read_registers(inst, MCII)) {
      if (is_taint_checked(reg, MRI)) {
        emitRawComment(Twine(" Begin taint check for ")
                           .concat(Twine(MRI.getName(reg)))
                           .concat(Twine(" ("))
                           .concat(Twine(std::to_string(reg)))
                           .concat(Twine(")")),
                       true);

        std::vector<MCInst> const insts{
            MCInstBuilder(X86::PUSHF64),
            MCInstBuilder(X86::PUSH64r).addReg(X86::RBP),
            MCInstBuilder(X86::MOV64rr).addReg(X86::RBP).addReg(X86::RSP),
            MCInstBuilder(X86::AND64ri8)
                .addReg(X86::RSP)
                .addReg(X86::RSP)
                .addImm(0xfffffffffffffff0ull),
            MCInstBuilder(X86::POP64r).addReg(X86::RBP),
            MCInstBuilder(X86::POPF64)};

        for (auto const &i : insts) {
          MCAsmStreamer::emitInstruction(i, STIArg);
        }

        emitRawComment(Twine(" End taint check for ")
                           .concat(Twine(MRI.getName(reg)))
                           .concat(Twine(" ("))
                           .concat(Twine(std::to_string(reg)))
                           .concat(Twine(")")),
                       true);
      }
    }

    for (auto const &reg : get_written_registers(inst, MCII)) {
      if (is_taint_checked(reg, MRI)) {
        emitRawComment(Twine(" Begin taint clear for: ")
                           .concat(Twine(MRI.getName(reg)))
                           .concat(Twine(" ("))
                           .concat(Twine(std::to_string(reg)))
                           .concat(Twine(")")),
                       true);
        emitRawComment(Twine(" End taint clear for: ")
                           .concat(Twine(MRI.getName(reg)))
                           .concat(Twine(" ("))
                           .concat(Twine(std::to_string(reg)))
                           .concat(Twine(")")),
                       true);
      }
    }

    MCAsmStreamer::emitInstruction(inst, STIArg);
  }

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override {
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
      *MCII, *STI, FPStreamer.global_symbol_names);
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
