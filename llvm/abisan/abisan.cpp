#include "Target/X86/MCTargetDesc/X86BaseInfo.h"
#include "Target/X86/MCTargetDesc/X86MCTargetDesc.h"
#include "Target/X86/X86.h"
#include "Target/X86/X86RegisterInfo.h"
#include "X86GenInstrInfo.inc"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAsmStreamer.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDirectives.h"
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

static std::vector<MCRegister>
get_written_registers(MCInst const &inst, MCInstrInfo const &MCII,
                      MCRegisterInfo const &MRI) {
  MCInstrDesc const &instr_desc = MCII.get(inst.getOpcode());

  std::vector<MCRegister> result;
  for (unsigned i = 0; i < MRI.getNumRegs(); i++) {
    MCRegister const reg = MCRegister::from(i);
    if (instr_desc.hasDefOfPhysReg(inst, reg, MRI)) {
      result.push_back(reg);
    }
  }
  if (inst.getOpcode() == X86::SYSCALL) {
    result.push_back(X86::RCX);
    result.push_back(X86::R11);
  }
  return result;
}

static std::vector<MCRegister> get_used_registers(MCInst const &inst,
                                                  MCInstrInfo const &MCII) {
  MCInstrDesc const &instr_desc = MCII.get(inst.getOpcode());

  std::vector<MCRegister> result;
  for (unsigned i = 0; i < inst.getNumOperands(); i++) {
    auto const &operand = inst.getOperand(i);
    if (operand.isReg() && operand.getReg() != 0) {
      result.push_back(operand.getReg());
    }
  }
  auto const &implicit_uses = instr_desc.implicit_uses();
  auto const &implicit_defs = instr_desc.implicit_defs();
  result.insert(result.end(), implicit_uses.begin(), implicit_uses.end());
  result.insert(result.end(), implicit_defs.begin(), implicit_defs.end());
  if (inst.getOpcode() == X86::SYSCALL) {
    result.push_back(X86::RCX); // written
    result.push_back(X86::R11); // written
    result.push_back(X86::RAX); // read
  }
  return result;
}

static std::vector<MCRegister> get_read_registers(MCInst const &inst,
                                                  MCInstrInfo const &MCII,
                                                  MCRegisterInfo const &MRI) {
  std::vector<MCRegister> result = get_used_registers(inst, MCII);
  std::vector<MCRegister> written_registers =
      get_written_registers(inst, MCII, MRI);
  for (auto const &written_register : written_registers) {
    auto the_find = std::find(result.begin(), result.end(), written_register);
    if (the_find != result.end()) {
      result.erase(the_find);
    }
  }

  std::vector<MCRegister> deduped_result;
  for (auto const &r1 : result) {
    bool dup = false;
    for (auto const &r2 : deduped_result) {
      if (r1 == r2) {
        dup = true;
        break;
      }
    }
    if (!dup) {
      deduped_result.push_back(r1);
    }
  }
  return deduped_result;
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
    MCAsmStreamer::emitInstruction(inst, STIArg);

    MCRegisterInfo const &MRI = *getContext().getRegisterInfo();

    for (auto const &reg : get_written_registers(inst, MCII, MRI)) {
      emitRawComment(Twine(" Writes: ")
                         .concat(Twine(MRI.getName(reg)))
                         .concat(Twine(" ("))
                         .concat(Twine(std::to_string(reg)))
                         .concat(Twine(")")),
                     true);
    }

    for (auto const &reg : get_read_registers(inst, MCII, MRI)) {
      emitRawComment(Twine(" Reads: ")
                         .concat(Twine(MRI.getName(reg)))
                         .concat(Twine(" ("))
                         .concat(Twine(std::to_string(reg)))
                         .concat(Twine(")")),
                     true);
    }
  }

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override {
    MCAsmStreamer::emitLabel(Symbol, Loc);
    for (auto const &instrumented_symbol_name : instrumented_symbol_names) {
      if (Symbol->getName().str() == instrumented_symbol_name) {
        MCInst call;
        call.setOpcode(X86::CALL64pcrel32);
        call.addOperand(MCOperand::createExpr(MCSymbolRefExpr::create(
            getContext().getOrCreateSymbol("__abisan_function_entry"),
            getContext())));
        MCAsmStreamer::emitInstruction(call, STI);
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
  return std::move(MOFI);
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
  Target const *const target = TargetRegistry::lookupTarget(triple_name, error);

  if (!target) {
    outs() << "Failed to lookup target: " << error << "\n";
    exit(1);
  }

  MCTargetOptions const options;
  std::shared_ptr<MCRegisterInfo const> MRI(target->createMCRegInfo(triple));
  std::shared_ptr<MCAsmInfo const> MAI(
      target->createMCAsmInfo(*MRI, triple, options));
  std::shared_ptr<MCSubtargetInfo const> STI(
      target->createMCSubtargetInfo(triple, "", ""));
  std::shared_ptr<MCInstrInfo const> MCII(target->createMCInstrInfo());

  std::unique_ptr<SourceMgr> const SM =
      make_sm(argv[1]); // Lifetime bound to Ctx
  MCContext Ctx(triple, MAI.get(), MRI.get(), STI.get(), SM.get());
  std::unique_ptr<MCObjectFileInfo const> MOFI =
      make_mofi(Ctx); // Lifetime bound to Ctx
  Ctx.setObjectFileInfo(MOFI.get());

  ABISanFirstPassStreamer FPStreamer(
      Ctx, std::make_unique<formatted_raw_ostream>(nulls()),
      std::unique_ptr<MCInstPrinter>(target->createMCInstPrinter(
          triple, MAI->getAssemblerDialect(), *MAI, *MCII, *MRI)),
      std::unique_ptr<MCCodeEmitter>(),
      std::unique_ptr<MCAsmBackend>(
          target->createMCAsmBackend(*STI, *MRI, options)));

  std::unique_ptr<MCAsmParser> FPParser(
      createMCAsmParser(*SM.get(), Ctx, FPStreamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> FPTargetParser(
      target->createMCAsmParser(*STI, *FPParser, *MCII, options));
  if (!FPTargetParser) {
    outs() << "No target-specific asm parser for triple!\n";
    exit(1);
  }
  FPParser->setTargetParser(*FPTargetParser);
  if (FPParser->Run(false)) {
    outs() << "Failed to parse assembly.\n";
    exit(1);
  }

  // Second pass starts here

  Ctx.reset();
  Ctx.setObjectFileInfo(MOFI.get());

  ABISanStreamer Streamer(
      Ctx, std::make_unique<formatted_raw_ostream>(outs()),
      std::unique_ptr<MCInstPrinter>(target->createMCInstPrinter(
          triple, MAI->getAssemblerDialect(), *MAI, *MCII, *MRI)),
      std::unique_ptr<MCCodeEmitter>(),
      std::unique_ptr<MCAsmBackend>(
          target->createMCAsmBackend(*STI, *MRI, options)),
      *MCII, *STI, FPStreamer.global_symbol_names);
  Streamer.initSections(false, *STI);

  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(*SM.get(), Ctx, Streamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> TargetParser(
      target->createMCAsmParser(*STI, *Parser, *MCII, options));
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
