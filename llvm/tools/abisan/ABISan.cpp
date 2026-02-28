/*
 * ABI Sanitizer
 * This is an unconventional kind of LLVM pass.
 * Basically, it instantiates a MCELFStreamer for x86-64 that
 * statically detects ABI violations, and emits
 * runtime checks for when it's uncertain.
 */

#include "ABISanInfo.h"                    // for ABISanInfo
#include "ABISanInstrumentation.h"         // for ABISanInstrumentation
#include "AMD64LinuxUserspaceABISanInfo.h" // for AMD64LinuxUserspaceABISanInfo
#include "AMD64LinuxUserspaceABISanInstrumentation.h" // for AMD64LinuxUserspaceABISanInstrumentation
#include "llvm/ADT/DenseSet.h"                        // for DenseSet
#include "llvm/ADT/SmallVector.h"               // for SmallVector
#include "llvm/ADT/Twine.h"                     // for Twine
#include "llvm/MC/MCAsmBackend.h"               // for MCAsmBackend
#include "llvm/MC/MCAsmInfo.h"                  // for MCAsmInfo
#include "llvm/MC/MCCodeEmitter.h"              // for MCCodeEmitter
#include "llvm/MC/MCContext.h"                  // for MCContext
#include "llvm/MC/MCELFStreamer.h"              // for MCELFStreamer
#include "llvm/MC/MCInstrInfo.h"                // for MCInstrInfo
#include "llvm/MC/MCObjectFileInfo.h"           // for MCObjectFileInfo
#include "llvm/MC/MCObjectWriter.h"             // for MCObjectWriter
#include "llvm/MC/MCParser/MCAsmParser.h"       // for MCAsmParser
#include "llvm/MC/MCParser/MCTargetAsmParser.h" // for MCTargetAsmParser
#include "llvm/MC/MCRegister.h"                 // for MCRegister
#include "llvm/MC/MCRegisterInfo.h"             // for MCRegisterInfo
#include "llvm/MC/MCSubtargetInfo.h"            // for MCSubtargetInfo
#include "llvm/MC/MCSymbol.h"                   // for MCSymbol
#include "llvm/MC/MCTargetOptions.h"            // for MCTargetOptions
#include "llvm/MC/TargetRegistry.h"             // for TargetRegistry
#include "llvm/Support/CommandLine.h"           // for cl::*
#include "llvm/Support/InitLLVM.h"              // for InitLLVM
#include "llvm/Support/MemoryBuffer.h"          // for MemoryBuffer::getFile
#include "llvm/Support/SMLoc.h"                 // for SMLoc
#include "llvm/Support/SourceMgr.h"             // for SourceMgr
#include "llvm/Support/TargetSelect.h" // for InitializeAllTargetInfos, InitializeAllTargetMCs, InitializeAllAsmParsers
#include "llvm/Support/VirtualFileSystem.h" // for vfs::getRealFileSystem
#include "llvm/Support/raw_ostream.h"       // for raw_fd_ostream
#include "llvm/TargetParser/Host.h"         // for getDefaultTargetTriple
#include <cassert>                          // for assert
#include <string>                           // for std::string
#include <variant> // for std::variant, std::holds_alternative, std::get

using namespace llvm;

static cl::OptionCategory ABISanCat("abisan-as Options");

static cl::opt<std::string> InputFilename(cl::Positional,
                                          cl::desc("<input .s file>"),
                                          cl::init("/dev/stdin"));

static cl::opt<std::string> OutputFilename("o",
                                           cl::desc("Override output filename"),
                                           cl::value_desc("filename"),
                                           cl::init("a.out"),
                                           cl::cat(ABISanCat));

static cl::opt<bool> Ignored0("64", cl::Hidden, cl::desc("Ignored"),
                              cl::cat(ABISanCat));

static cl::opt<bool> Ignored1("gdwarf-5", cl::Hidden, cl::desc("Ignored"),
                              cl::cat(ABISanCat));

static cl::opt<bool> Ignored2("noexecstack", cl::Hidden, cl::desc("Ignored"),
                              cl::cat(ABISanCat));

static cl::opt<bool> Ignored3("v", cl::Hidden, cl::desc("Ignored"),
                              cl::cat(ABISanCat));

static cl::opt<bool> Ignored4("g", cl::Hidden, cl::desc("Ignored"),
                              cl::cat(ABISanCat));

static cl::list<std::string> IncludeDirs("I",
                                         cl::desc("Directory of include files"),
                                         cl::value_desc("directory"),
                                         cl::Prefix, cl::cat(ABISanCat));

class ABISanFirstPassStreamer : public MCELFStreamer {
  // This class exists to make a first pass over the .s file to collect
  // all the names of the functions we want to instrument.
private:
  DenseSet<StringRef> ProtectedSymbolNames;

public:
  DenseSet<StringRef> ABISymbolNames;
  DenseSet<StringRef> NonABISymbolNames;

  ABISanFirstPassStreamer(MCContext &Context, std::unique_ptr<MCAsmBackend> MAB,
                          std::unique_ptr<MCObjectWriter> OW,
                          std::unique_ptr<MCCodeEmitter> Emitter)
      : MCELFStreamer(Context, std::move(MAB), std::move(OW),
                      std::move(Emitter)) {}

  bool emitSymbolAttribute(MCSymbol *Symbol, MCSymbolAttr Attribute) override {
    auto const SymbolName = Symbol->getName();
    if (Attribute == MCSA_Global &&
        !ProtectedSymbolNames.contains(SymbolName)) {
      if (NonABISymbolNames.contains(SymbolName)) {
        NonABISymbolNames.erase(SymbolName);
      }
      ABISymbolNames.insert(Symbol->getName());
    } else if (Attribute == MCSA_Protected || Attribute == MCSA_Hidden ||
               Attribute == MCSA_Internal) {
      if (ABISymbolNames.contains(SymbolName)) {
        ABISymbolNames.erase(SymbolName);
      }
      if (!ProtectedSymbolNames.contains(SymbolName)) {
        ProtectedSymbolNames.insert(SymbolName);
      }
    }
    return MCELFStreamer::emitSymbolAttribute(Symbol, Attribute);
  }

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override {
    MCELFStreamer::emitLabel(Symbol, Loc);
    if (Symbol->getOffset() != 0) {
      return;
    }
    auto const SymbolName = Symbol->getName();
    if (!ABISymbolNames.contains(SymbolName)) {
      NonABISymbolNames.insert(SymbolName);
    }
  }
};

class ABISanStreamer : public MCELFStreamer {
  // Does the instrumentation :)

  MCSubtargetInfo const &STI;
  ABISanInstrumentation &ABIInstrumentation;

  void emit(ArrayRef<std::variant<MCInst, MCSymbol *>> InstsAndSymbols) {
    for (auto V : InstsAndSymbols) {
      if (std::holds_alternative<MCInst>(V)) {
        MCELFStreamer::emitInstruction(std::get<MCInst>(V), STI);
      } else if (std::holds_alternative<MCSymbol *>(V)) {
        MCELFStreamer::emitLabel(std::get<MCSymbol *>(V));
      } else {
        assert(false);
      }
    }
  }

public:
  ABISanStreamer(MCContext &Context, std::unique_ptr<MCAsmBackend> MAB,
                 std::unique_ptr<MCObjectWriter> OW,
                 std::unique_ptr<MCCodeEmitter> Emitter,
                 MCSubtargetInfo const &STI,
                 ABISanInstrumentation &ABIInstrumentation)
      : MCELFStreamer(Context, std::move(MAB), std::move(OW),
                      std::move(Emitter)),
        STI(STI), ABIInstrumentation(ABIInstrumentation) {}

  void emitInstruction(MCInst const &Inst, MCSubtargetInfo const &) override {
    // STI arg is ignored because I need it in emit, so it's a member
    emit(ABIInstrumentation.instrumentInstruction(Inst, getStartTokLoc()));
  }

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override {
    MCELFStreamer::emitLabel(Symbol, Loc);
    emit(ABIInstrumentation.instrumentLabel(Symbol, Loc));
  }
};

int main(int argc, char const **argv) {
  InitLLVM TheInit(argc, argv);
  cl::HideUnrelatedOptions(ABISanCat);
  cl::ParseCommandLineOptions(argc, argv, "ABI Sanitizer assembler\n");

  std::error_code EC;
  raw_fd_ostream OutputFile(OutputFilename, EC);
  if (EC) {
    errs() << "Failed to open output file!\n";
    exit(1);
  }

  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllAsmParsers();

  std::string Error;
  Triple const TheTriple(sys::getDefaultTargetTriple());
  Target const *const Target = TargetRegistry::lookupTarget(TheTriple, Error);

  if (!Target) {
    errs() << "Failed to look up target: " << Error << "\n";
    exit(1);
  }

  MCTargetOptions const Options;
  std::shared_ptr<MCRegisterInfo const> MRI(Target->createMCRegInfo(TheTriple));
  std::shared_ptr<MCAsmInfo const> MAI(
      Target->createMCAsmInfo(*MRI, TheTriple, Options));
  std::shared_ptr<MCSubtargetInfo const> STI(
      Target->createMCSubtargetInfo(TheTriple, "", ""));
  std::shared_ptr<MCInstrInfo const> MCII(Target->createMCInstrInfo());

  std::unique_ptr<SourceMgr> SM = std::make_unique<SourceMgr>();
  auto BufferOrError = MemoryBuffer::getFile(InputFilename);
  if (!BufferOrError) {
    errs() << "Error reading file: " << InputFilename << "\n";
    exit(1);
  }

  SM->AddNewSourceBuffer(std::move(*BufferOrError), SMLoc());
  SM->setIncludeDirs(IncludeDirs);
  SM->setVirtualFileSystem(vfs::getRealFileSystem());

  MCContext FPCtx(TheTriple, MAI.get(), MRI.get(), STI.get(), SM.get(),
                  &Options);
  std::unique_ptr<MCObjectFileInfo> FPMOFI =
      std::make_unique<MCObjectFileInfo>();
  FPMOFI->initMCObjectFileInfo(FPCtx, false);
  FPCtx.setObjectFileInfo(FPMOFI.get());

  // First pass starts here.
  // The point of the first pass is to locate all the symbols that need to be
  // instrumented.

  SmallVector<char> IgnoredSvector;
  raw_svector_ostream IgnoredOstream(IgnoredSvector);
  std::unique_ptr<MCAsmBackend> FPMAB(
      Target->createMCAsmBackend(*STI, *MRI, Options));
  std::unique_ptr<MCObjectWriter> FPOW(
      FPMAB->createObjectWriter(IgnoredOstream));

  ABISanFirstPassStreamer FPStreamer(
      FPCtx, std::move(FPMAB), std::move(FPOW),
      std::unique_ptr<MCCodeEmitter>(
          Target->createMCCodeEmitter(*MCII, FPCtx)));

  std::unique_ptr<MCAsmParser> FPParser(
      createMCAsmParser(*SM.get(), FPCtx, FPStreamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> FPTargetParser(
      Target->createMCAsmParser(*STI, *FPParser, *MCII, Options));
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

  MCContext Ctx(TheTriple, MAI.get(), MRI.get(), STI.get(), SM.get(), &Options);
  std::unique_ptr<MCObjectFileInfo> MOFI = std::make_unique<MCObjectFileInfo>();
  MOFI->initMCObjectFileInfo(Ctx, false);
  Ctx.setObjectFileInfo(MOFI.get());

  std::unique_ptr<MCAsmBackend> MAB(
      Target->createMCAsmBackend(*STI, *MRI, Options));
  std::unique_ptr<MCObjectWriter> OW(MAB->createObjectWriter(OutputFile));

  AMD64LinuxUserspaceABISanInfo const ABIInfo(
      *MRI, *MCII, FPStreamer.NonABISymbolNames, FPStreamer.ABISymbolNames);
  AMD64LinuxUserspaceABISanInstrumentation ABIInstrumentation(Ctx, ABIInfo);

  ABISanStreamer Streamer(
      Ctx, std::move(MAB), std::move(OW),
      std::unique_ptr<MCCodeEmitter>(Target->createMCCodeEmitter(*MCII, Ctx)),
      *STI, ABIInstrumentation);
  Streamer.initSections(false, *STI);

  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(*SM.get(), Ctx, Streamer, *MAI));
  std::unique_ptr<MCTargetAsmParser> TargetParser(
      Target->createMCAsmParser(*STI, *Parser, *MCII, Options));
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
