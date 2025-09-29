//===- lib/MC/MCAsmStreamer.cpp - Text Assembly Output ----------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Twine.h"
#include "llvm/DebugInfo/CodeView/SymbolRecord.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCCodeView.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCPseudoProbe.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbolXCOFF.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/Path.h"
#include <algorithm>
#include <optional>

using namespace llvm;

class MCAsmStreamer : public MCStreamer {
  std::unique_ptr<formatted_raw_ostream> OSOwner;
  formatted_raw_ostream &OS;
  const MCAsmInfo *MAI;
  std::unique_ptr<MCInstPrinter> InstPrinter;
  std::unique_ptr<MCAssembler> Assembler;

  SmallString<128> ExplicitCommentToEmit;
  SmallString<128> CommentToEmit;
  raw_svector_ostream CommentStream;
  raw_null_ostream NullStream;

  bool EmittedSectionDirective = false;

  bool IsVerboseAsm = false;
  bool ShowInst = false;
  bool UseDwarfDirectory = false;

  void EmitRegisterName(int64_t Register);
  void PrintQuotedString(StringRef Data, raw_ostream &OS) const;
  void printDwarfFileDirective(unsigned FileNo, StringRef Directory,
                               StringRef Filename,
                               std::optional<MD5::MD5Result> Checksum,
                               std::optional<StringRef> Source,
                               bool UseDwarfDirectory,
                               raw_svector_ostream &OS) const;
  void emitCFIStartProcImpl(MCDwarfFrameInfo &Frame) override;
  void emitCFIEndProcImpl(MCDwarfFrameInfo &Frame) override;

public:
  MCAsmStreamer(MCContext &Context, std::unique_ptr<formatted_raw_ostream> os,
                std::unique_ptr<MCInstPrinter> printer,
                std::unique_ptr<MCCodeEmitter> emitter,
                std::unique_ptr<MCAsmBackend> asmbackend);

  MCAssembler &getAssembler();
  MCAssembler *getAssemblerPtr() override;

  inline void EmitEOL() {
    // Dump Explicit Comments here.
    emitExplicitComments();
    // If we don't have any comments, just emit a \n.
    if (!IsVerboseAsm) {
      OS << '\n';
      return;
    }
    EmitCommentsAndEOL();
  }

  void emitSyntaxDirective() override;

  void EmitCommentsAndEOL();

  /// Return true if this streamer supports verbose assembly at all.
  bool isVerboseAsm() const override;

  /// Do we support EmitRawText?
  bool hasRawTextSupport() const override;

  /// Add a comment that can be emitted to the generated .s file to make the
  /// output of the compiler more readable. This only affects the MCAsmStreamer
  /// and only when verbose assembly output is enabled.
  void AddComment(const Twine &T, bool EOL = true) override;

  /// Add a comment showing the encoding of an instruction.
  void AddEncodingComment(const MCInst &Inst, const MCSubtargetInfo &);

  /// Return a raw_ostream that comments can be written to.
  /// Unlike AddComment, you are required to terminate comments with \n if you
  /// use this method.
  raw_ostream &getCommentOS() override;

  void emitRawComment(const Twine &T, bool TabPrefix = true) override;

  void addExplicitComment(const Twine &T) override;
  void emitExplicitComments() override;

  /// Emit a blank line to a .s file to pretty it up.
  void addBlankLine() override;

  /// @name MCStreamer Interface
  /// @{

  void switchSection(MCSection *Section, uint32_t Subsection) override;
  bool popSection() override;

  void emitELFSymverDirective(const MCSymbol *OriginalSym, StringRef Name,
                              bool KeepOriginalSym) override;

  void emitLOHDirective(MCLOHType Kind, const MCLOHArgs &Args) override;

  void emitGNUAttribute(unsigned Tag, unsigned Value) override;

  StringRef getMnemonic(const MCInst &MI) const override;

  void emitLabel(MCSymbol *Symbol, SMLoc Loc = SMLoc()) override;

  void emitSubsectionsViaSymbols() override;
  void emitLinkerOptions(ArrayRef<std::string> Options) override;
  void emitDataRegion(MCDataRegionType Kind) override;
  void emitVersionMin(MCVersionMinType Kind, unsigned Major, unsigned Minor,
                      unsigned Update, VersionTuple SDKVersion) override;
  void emitBuildVersion(unsigned Platform, unsigned Major, unsigned Minor,
                        unsigned Update, VersionTuple SDKVersion) override;
  void emitDarwinTargetVariantBuildVersion(unsigned Platform, unsigned Major,
                                           unsigned Minor, unsigned Update,
                                           VersionTuple SDKVersion) override;

  void emitAssignment(MCSymbol *Symbol, const MCExpr *Value) override;
  void emitConditionalAssignment(MCSymbol *Symbol,
                                 const MCExpr *Value) override;
  void emitWeakReference(MCSymbol *Alias, const MCSymbol *Symbol) override;
  bool emitSymbolAttribute(MCSymbol *Symbol, MCSymbolAttr Attribute) override;

  void emitSymbolDesc(MCSymbol *Symbol, unsigned DescValue) override;
  void beginCOFFSymbolDef(const MCSymbol *Symbol) override;
  void emitCOFFSymbolStorageClass(int StorageClass) override;
  void emitCOFFSymbolType(int Type) override;
  void endCOFFSymbolDef() override;
  void emitCOFFSafeSEH(MCSymbol const *Symbol) override;
  void emitCOFFSymbolIndex(MCSymbol const *Symbol) override;
  void emitCOFFSectionIndex(MCSymbol const *Symbol) override;
  void emitCOFFSecRel32(MCSymbol const *Symbol, uint64_t Offset) override;
  void emitCOFFImgRel32(MCSymbol const *Symbol, int64_t Offset) override;
  void emitCOFFSecNumber(MCSymbol const *Symbol) override;
  void emitCOFFSecOffset(MCSymbol const *Symbol) override;
  void emitXCOFFLocalCommonSymbol(MCSymbol *LabelSym, uint64_t Size,
                                  MCSymbol *CsectSym, Align Alignment) override;
  void emitXCOFFSymbolLinkageWithVisibility(MCSymbol *Symbol,
                                            MCSymbolAttr Linkage,
                                            MCSymbolAttr Visibility) override;
  void emitXCOFFRenameDirective(const MCSymbol *Name,
                                StringRef Rename) override;

  void emitXCOFFRefDirective(const MCSymbol *Symbol) override;

  void emitXCOFFExceptDirective(const MCSymbol *Symbol, const MCSymbol *Trap,
                                unsigned Lang, unsigned Reason,
                                unsigned FunctionSize, bool hasDebug) override;
  void emitXCOFFCInfoSym(StringRef Name, StringRef Metadata) override;

  void emitELFSize(MCSymbol *Symbol, const MCExpr *Value) override;
  void emitCommonSymbol(MCSymbol *Symbol, uint64_t Size,
                        Align ByteAlignment) override;

  /// Emit a local common (.lcomm) symbol.
  ///
  /// @param Symbol - The common symbol to emit.
  /// @param Size - The size of the common symbol.
  /// @param ByteAlignment - The alignment of the common symbol in bytes.
  void emitLocalCommonSymbol(MCSymbol *Symbol, uint64_t Size,
                             Align ByteAlignment) override;

  void emitZerofill(MCSection *Section, MCSymbol *Symbol = nullptr,
                    uint64_t Size = 0, Align ByteAlignment = Align(1),
                    SMLoc Loc = SMLoc()) override;

  void emitTBSSSymbol(MCSection *Section, MCSymbol *Symbol, uint64_t Size,
                      Align ByteAlignment = Align(1)) override;

  void emitBinaryData(StringRef Data) override;

  void emitBytes(StringRef Data) override;

  void emitValueImpl(const MCExpr *Value, unsigned Size,
                     SMLoc Loc = SMLoc()) override;
  void emitIntValue(uint64_t Value, unsigned Size) override;
  void emitIntValueInHex(uint64_t Value, unsigned Size) override;
  void emitIntValueInHexWithPadding(uint64_t Value, unsigned Size) override;

  void emitULEB128Value(const MCExpr *Value) override;

  void emitSLEB128Value(const MCExpr *Value) override;

  void emitFill(const MCExpr &NumBytes, uint64_t FillValue,
                SMLoc Loc = SMLoc()) override;

  void emitFill(const MCExpr &NumValues, int64_t Size, int64_t Expr,
                SMLoc Loc = SMLoc()) override;

  void emitAlignmentDirective(uint64_t ByteAlignment,
                              std::optional<int64_t> Value, unsigned ValueSize,
                              unsigned MaxBytesToEmit);

  void emitValueToAlignment(Align Alignment, int64_t Fill = 0,
                            uint8_t FillLen = 1,
                            unsigned MaxBytesToEmit = 0) override;

  void emitCodeAlignment(Align Alignment, const MCSubtargetInfo *STI,
                         unsigned MaxBytesToEmit = 0) override;

  void emitValueToOffset(const MCExpr *Offset, unsigned char Value,
                         SMLoc Loc) override;

  void emitFileDirective(StringRef Filename) override;
  void emitFileDirective(StringRef Filename, StringRef CompilerVersion,
                         StringRef TimeStamp, StringRef Description) override;
  Expected<unsigned> tryEmitDwarfFileDirective(
      unsigned FileNo, StringRef Directory, StringRef Filename,
      std::optional<MD5::MD5Result> Checksum = std::nullopt,
      std::optional<StringRef> Source = std::nullopt,
      unsigned CUID = 0) override;
  void emitDwarfFile0Directive(StringRef Directory, StringRef Filename,
                               std::optional<MD5::MD5Result> Checksum,
                               std::optional<StringRef> Source,
                               unsigned CUID = 0) override;
  void emitDwarfLocDirective(unsigned FileNo, unsigned Line, unsigned Column,
                             unsigned Flags, unsigned Isa,
                             unsigned Discriminator, StringRef FileName,
                             StringRef Location = {}) override;
  virtual void emitDwarfLocLabelDirective(SMLoc Loc, StringRef Name) override;

  MCSymbol *getDwarfLineTableSymbol(unsigned CUID) override;

  bool emitCVFileDirective(unsigned FileNo, StringRef Filename,
                           ArrayRef<uint8_t> Checksum,
                           unsigned ChecksumKind) override;
  bool emitCVFuncIdDirective(unsigned FuncId) override;
  bool emitCVInlineSiteIdDirective(unsigned FunctionId, unsigned IAFunc,
                                   unsigned IAFile, unsigned IALine,
                                   unsigned IACol, SMLoc Loc) override;
  void emitCVLocDirective(unsigned FunctionId, unsigned FileNo, unsigned Line,
                          unsigned Column, bool PrologueEnd, bool IsStmt,
                          StringRef FileName, SMLoc Loc) override;
  void emitCVLinetableDirective(unsigned FunctionId, const MCSymbol *FnStart,
                                const MCSymbol *FnEnd) override;
  void emitCVInlineLinetableDirective(unsigned PrimaryFunctionId,
                                      unsigned SourceFileId,
                                      unsigned SourceLineNum,
                                      const MCSymbol *FnStartSym,
                                      const MCSymbol *FnEndSym) override;

  void PrintCVDefRangePrefix(
      ArrayRef<std::pair<const MCSymbol *, const MCSymbol *>> Ranges);

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol *, const MCSymbol *>> Ranges,
      codeview::DefRangeRegisterRelHeader DRHdr) override;

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol *, const MCSymbol *>> Ranges,
      codeview::DefRangeSubfieldRegisterHeader DRHdr) override;

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol *, const MCSymbol *>> Ranges,
      codeview::DefRangeRegisterHeader DRHdr) override;

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol *, const MCSymbol *>> Ranges,
      codeview::DefRangeFramePointerRelHeader DRHdr) override;

  void emitCVStringTableDirective() override;
  void emitCVFileChecksumsDirective() override;
  void emitCVFileChecksumOffsetDirective(unsigned FileNo) override;
  void emitCVFPOData(const MCSymbol *ProcSym, SMLoc L) override;

  void emitIdent(StringRef IdentString) override;
  void emitCFIBKeyFrame() override;
  void emitCFIMTETaggedFrame() override;
  void emitCFISections(bool EH, bool Debug, bool SFrame) override;
  void emitCFIDefCfa(int64_t Register, int64_t Offset, SMLoc Loc) override;
  void emitCFIDefCfaOffset(int64_t Offset, SMLoc Loc) override;
  void emitCFIDefCfaRegister(int64_t Register, SMLoc Loc) override;
  void emitCFILLVMDefAspaceCfa(int64_t Register, int64_t Offset,
                               int64_t AddressSpace, SMLoc Loc) override;
  void emitCFIOffset(int64_t Register, int64_t Offset, SMLoc Loc) override;
  void emitCFIPersonality(const MCSymbol *Sym, unsigned Encoding) override;
  void emitCFILsda(const MCSymbol *Sym, unsigned Encoding) override;
  void emitCFIRememberState(SMLoc Loc) override;
  void emitCFIRestoreState(SMLoc Loc) override;
  void emitCFIRestore(int64_t Register, SMLoc Loc) override;
  void emitCFISameValue(int64_t Register, SMLoc Loc) override;
  void emitCFIRelOffset(int64_t Register, int64_t Offset, SMLoc Loc) override;
  void emitCFIAdjustCfaOffset(int64_t Adjustment, SMLoc Loc) override;
  void emitCFIEscape(StringRef Values, SMLoc Loc) override;
  void emitCFIGnuArgsSize(int64_t Size, SMLoc Loc) override;
  void emitCFISignalFrame() override;
  void emitCFIUndefined(int64_t Register, SMLoc Loc) override;
  void emitCFIRegister(int64_t Register1, int64_t Register2,
                       SMLoc Loc) override;
  void emitCFIWindowSave(SMLoc Loc) override;
  void emitCFINegateRAState(SMLoc Loc) override;
  void emitCFINegateRAStateWithPC(SMLoc Loc) override;
  void emitCFIReturnColumn(int64_t Register) override;
  void emitCFILabelDirective(SMLoc Loc, StringRef Name) override;
  void emitCFIValOffset(int64_t Register, int64_t Offset, SMLoc Loc) override;

  void emitWinCFIStartProc(const MCSymbol *Symbol, SMLoc Loc) override;
  void emitWinCFIEndProc(SMLoc Loc) override;
  void emitWinCFIFuncletOrFuncEnd(SMLoc Loc) override;
  void emitWinCFIStartChained(SMLoc Loc) override;
  void emitWinCFIEndChained(SMLoc Loc) override;
  void emitWinCFIPushReg(MCRegister Register, SMLoc Loc) override;
  void emitWinCFISetFrame(MCRegister Register, unsigned Offset,
                          SMLoc Loc) override;
  void emitWinCFIAllocStack(unsigned Size, SMLoc Loc) override;
  void emitWinCFISaveReg(MCRegister Register, unsigned Offset,
                         SMLoc Loc) override;
  void emitWinCFISaveXMM(MCRegister Register, unsigned Offset,
                         SMLoc Loc) override;
  void emitWinCFIPushFrame(bool Code, SMLoc Loc) override;
  void emitWinCFIEndProlog(SMLoc Loc) override;
  void emitWinCFIBeginEpilogue(SMLoc Loc) override;
  void emitWinCFIEndEpilogue(SMLoc Loc) override;
  void emitWinCFIUnwindV2Start(SMLoc Loc) override;
  void emitWinCFIUnwindVersion(uint8_t Version, SMLoc Loc) override;

  void emitWinEHHandler(const MCSymbol *Sym, bool Unwind, bool Except,
                        SMLoc Loc) override;
  void emitWinEHHandlerData(SMLoc Loc) override;

  void emitCGProfileEntry(const MCSymbolRefExpr *From,
                          const MCSymbolRefExpr *To, uint64_t Count) override;

  void emitInstruction(const MCInst &Inst, const MCSubtargetInfo &STI) override;

  void emitPseudoProbe(uint64_t Guid, uint64_t Index, uint64_t Type,
                       uint64_t Attr, uint64_t Discriminator,
                       const MCPseudoProbeInlineStack &InlineStack,
                       MCSymbol *FnSym) override;

  void emitRelocDirective(const MCExpr &Offset, StringRef Name,
                          const MCExpr *Expr, SMLoc Loc) override;

  void emitAddrsig() override;
  void emitAddrsigSym(const MCSymbol *Sym) override;

  /// If this file is backed by an assembly streamer, this dumps the specified
  /// string in the output .s file. This capability is indicated by the
  /// hasRawTextSupport() predicate.
  void emitRawTextImpl(StringRef String) override;

  void finishImpl() override;

  void emitDwarfUnitLength(uint64_t Length, const Twine &Comment) override;

  MCSymbol *emitDwarfUnitLength(const Twine &Prefix,
                                const Twine &Comment) override;

  void emitDwarfLineStartLabel(MCSymbol *StartSym) override;

  void emitDwarfLineEndEntry(MCSection *Section, MCSymbol *LastLabel,
                             MCSymbol *EndLabel = nullptr) override;

  void emitDwarfAdvanceLineAddr(int64_t LineDelta, const MCSymbol *LastLabel,
                                const MCSymbol *Label,
                                unsigned PointerSize) override;
};
