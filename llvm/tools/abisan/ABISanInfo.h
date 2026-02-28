#ifndef LLVM_TOOLS_ABISAN_ABISANINFO_H
#define LLVM_TOOLS_ABISAN_ABISANINFO_H

// Contains all the immutable state of the pass.
// Should be able to answer questions of the form
// "What X does this Y affect, and how?"

#include "llvm/ADT/DenseSet.h"  // for DenseSet
#include "llvm/ADT/StringRef.h" // for StringRef
#include "llvm/ADT/Twine.h"     // for Twine
#include "llvm/MC/MCExpr.h" // for MCExpr, MCSymbolRefExpr, MCBinaryExpr, MCSpecifierExpr, MCUnaryExpr
#include "llvm/MC/MCInst.h"         // for MCInst
#include "llvm/MC/MCInstrInfo.h"    // for MCInstrInfo
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCRegisterInfo.h" // for MCRegisterInfo
#include "llvm/MC/MCSymbol.h"       // for MCSymbol
#include "llvm/Support/Casting.h"   // for cast
#include <algorithm>                // for std::max
#include <cassert>                  // for assert
#include <climits>                  // for UINT_MAX
#include <cstdint>                  // for uint8_t

namespace llvm {

inline MCSymbolRefExpr const *getMCSymbolRefExpr(MCExpr const &Expr) {
  // Returns a MCSymbolRefExpr referenced in this expression.
  // If there are multiple, just returns one.
  // TODO: Figure out if we ever see direct call expressions that reference
  // multiple symbols in the wild

  switch (Expr.getKind()) {
  case MCExpr::Constant:
  case MCExpr::Target:
    // TODO: figure out if Target requires some special handling
    return nullptr;
  case MCExpr::SymbolRef:
    return (MCSymbolRefExpr const *)&Expr;
  case MCExpr::Unary:
    return getMCSymbolRefExpr(*cast<MCUnaryExpr>(Expr).getSubExpr());
  case MCExpr::Specifier:
    return getMCSymbolRefExpr(*cast<MCSpecifierExpr>(Expr).getSubExpr());
  case MCExpr::Binary: {
    auto const *LResult =
        getMCSymbolRefExpr(*cast<MCBinaryExpr>(Expr).getLHS());
    if (LResult) {
      return LResult;
    }
    auto const *RResult =
        getMCSymbolRefExpr(*cast<MCBinaryExpr>(Expr).getRHS());
    if (RResult) {
      return RResult;
    }
    return nullptr;
  }
  }
}

class ABISanInfo {
protected:
  MCRegisterInfo const &MRI;
  MCInstrInfo const &MCII;
  DenseSet<StringRef> const &NonABISymbolNames;
  DenseSet<StringRef> const &ABISymbolNames;

  DenseSet<MCRegister>
  deduplicateSubregisters(DenseSet<MCRegister> const Regs) const {
    DenseSet<MCRegister> Result;
    for (auto Reg : Regs) {
      bool FoundSuper = false;
      for (auto PotentialSuper : Regs) {
        if (MRI.isSubRegister(PotentialSuper, Reg)) {
          FoundSuper = true;
          break;
        }
      }
      if (!FoundSuper) {
        Result.insert(Reg);
      }
    }
    return Result;
  }

public:
  ABISanInfo(MCRegisterInfo const &MRI, MCInstrInfo const &MCII,
             DenseSet<StringRef> const &NonABISymbolNames,
             DenseSet<StringRef> const &ABISymbolNames)
      : MRI(MRI), MCII(MCII), NonABISymbolNames(NonABISymbolNames),
        ABISymbolNames(ABISymbolNames) {}

  virtual ~ABISanInfo() = default;

  virtual DenseSet<MCRegister> const &getTaintTrackedSuperregisters() const = 0;

  virtual DenseSet<MCRegister> const &getNonvolatileSuperregisters() const = 0;

  virtual DenseSet<MCRegister> const &getMainArgumentSuperregisters() const = 0;

  virtual DenseSet<MCRegister> const &getNonArgumentSuperregisters() const = 0;

  virtual DenseSet<MCRegister> const &getNonArgumentSubregisters() const = 0;

  virtual DenseSet<MCRegister> const &getArgumentSuperregisters() const = 0;

  virtual unsigned getRedzoneSize() const = 0;

  virtual unsigned getShadowStackRetAddrOffset() const = 0;

  virtual unsigned getShadowStackFrameSize() const = 0;

  virtual unsigned getRegisterSize(MCRegister const Reg) const {
    unsigned Result = 0;
    for (auto const &RC : MRI.regclasses()) {
      if (RC.contains(Reg)) {
        Result = std::max(RC.getSizeInBits(), Result);
      }
    }
    assert(Result > 0);
    return Result;
  }

  std::string getMemoryCheckSymbolName(void) const {
    return "__abisan_memory_check";
  }

  std::string getTaintClearSymbolName(MCRegister const Reg) const {
    return Twine("__abisan_taint_clear_").concat(MRI.getName(Reg)).str();
  }

  std::string getTaintCheckSymbolName(MCRegister const Reg) const {
    return Twine("__abisan_taint_check_").concat(MRI.getName(Reg)).str();
  }

  std::string getTaintCopySymbolName(MCRegister const Dst,
                                     MCRegister const Src) const {
    assert(getMatchingRegister(Dst, Src) == Dst);
    return Twine("__abisan_taint_copy_from_")
        .concat(MRI.getName(Src))
        .concat("_to_")
        .concat(MRI.getName(Dst))
        .str();
  }

  std::string getTaintSetSymbolName(MCRegister const Reg) const {
    return Twine("__abisan_taint_set_").concat(MRI.getName(Reg)).str();
  }

  bool accessesMemory(MCInst const &Inst) const {
    auto const &MID = MCII.get(Inst.getOpcode());
    for (auto const &Op : MID.operands()) {
      if (Op.OperandType == MCOI::OPERAND_MEMORY) {
        return true;
      }
    }
    return false;
  }

  unsigned findMemoryOperand(MCInst const &Inst) const {
    unsigned I = 0;
    for (auto const &Op : MCII.get(Inst.getOpcode()).operands()) {
      if (Op.OperandType == MCOI::OPERAND_MEMORY) {
        return I;
      }
      I++;
    }
    assert(false);
  }

  bool isNonABICall(MCInst const &Inst) const {
    return MCII.get(Inst.getOpcode()).isCall() && !isABICall(Inst);
  }

  bool isABICall(MCInst const &Inst) const {
    if (!MCII.get(Inst.getOpcode()).isCall()) {
      return false;
    }
    for (auto Operand : Inst) {
      if (Operand.isExpr()) {
        MCSymbolRefExpr const *SymbolRefExprOrNull =
            getMCSymbolRefExpr(*Operand.getExpr());
        if (SymbolRefExprOrNull) {
          auto const SymbolName = SymbolRefExprOrNull->getSymbol().getName();
          if (SymbolName.starts_with(".L") ||
              NonABISymbolNames.contains(SymbolName)) {
            return false;
          }
        }
      }
    }
    return true;
  }

  virtual bool isSyscall(MCInst const &) const = 0;

  virtual bool isRet(MCInst const &) const = 0;

  virtual DenseSet<MCRegister> const &
  getSyscallDirtiedSuperregisters() const = 0;

  virtual DenseSet<MCRegister> const &
  getABICallDirtiedSuperregisters() const = 0;

  DenseSet<MCRegister> const
  getDirtiedSuperregisters(MCInst const &Inst) const {
    if (isSyscall(Inst)) {
      return getSyscallDirtiedSuperregisters();
    }
    if (isABICall(Inst)) {
      return getABICallDirtiedSuperregisters();
    }
    return {};
  }

  virtual DenseSet<MCRegister> const &getRetvalSuperregisters() const = 0;

  virtual bool unknownsWrittenRegisters(MCInst const &Inst) const = 0;

  virtual bool needsTaintCopy(MCInst const &Inst) const = 0;

  DenseSet<MCRegister> const
  getUnknownedSuperregisters(MCInst const &Inst) const {
    if (isABICall(Inst)) {
      return getRetvalSuperregisters();
    }
    if (isNonABICall(Inst)) {
      return getTaintTrackedSuperregisters();
    }
    if (unknownsWrittenRegisters(Inst)) {
      return getWrittenSuperregisters(Inst);
    }
    return {};
  }

  DenseSet<MCRegister> const
  getCleanedSuperregisters(MCInst const &Inst) const {
    // Returns the registers that are unconditionally cleaned by this
    // instruction
    if (unknownsWrittenRegisters(Inst) || needsTaintCopy(Inst)) {
      return {};
    }
    return getWrittenSuperregisters(Inst);
  }

  MCRegister getLargestSuperregister(MCRegister const Reg) const {
    // Inclusive
    MCRegister Result = Reg;
    unsigned ResultSize = getRegisterSize(Reg);
    for (auto const Superreg : MRI.superregs(Reg)) {
      unsigned const SuperSize = getRegisterSize(Superreg);
      if (SuperSize > ResultSize) {
        Result = Superreg;
        ResultSize = SuperSize;
      }
    }
    return Result;
  }

  MCRegister getSmallestSuperregister(MCRegister const Reg) const {
    // Exclusive
    MCRegister Result = Reg;
    unsigned ResultSize = UINT_MAX;
    for (auto const Superreg : MRI.superregs(Reg)) {
      unsigned const SuperSize = getRegisterSize(Superreg);
      if (SuperSize < ResultSize) {
        Result = Superreg;
        ResultSize = SuperSize;
      }
    }
    assert(ResultSize != UINT_MAX && Result != Reg);
    return Result;
  }

  MCRegister getMatchingRegister(MCRegister const Super,
                                 MCRegister const Match) const {
    // Returns the (super|sub)register of Super that corresponds to Match.
    // e.g., getMatchingRegister(X86::AX, X86::DL) returns X86::AL
    // Returns 0 if there is no corresponding register.
    auto const SuperSuper = getLargestSuperregister(Super);
    auto const SuperMatch = getLargestSuperregister(Match);
    assert(getRegisterSize(SuperSuper) == getRegisterSize(SuperMatch));
    auto const SubRegIndex = MRI.getSubRegIndex(SuperMatch, Match);
    return SubRegIndex != 0 ? MRI.getSubReg(SuperSuper, SubRegIndex)
                            : SuperSuper;
  }

  MCRegister getSuperregister(MCRegister const Reg, unsigned const Size) const {
    for (auto const Superreg : MRI.superregs(Reg)) {
      unsigned const SuperSize = getRegisterSize(Superreg);
      if (SuperSize == Size) {
        return Superreg;
      }
    }
    assert(false);
  }

  bool isFullWidth(MCRegister const Reg) const {
    return Reg == getLargestSuperregister(Reg);
  }

  virtual DenseSet<MCRegister> getReadSuperregisters(MCInst const &Inst) const {
    // Returns the full set of registers that this instruction reads,
    // deduplicated by superregisters. That is, for an instruction that reads
    // both rax and eax, we return {rax}.
    DenseSet<MCRegister> Result;
    auto const &MID = MCII.get(Inst.getOpcode());
    for (unsigned I = MID.getNumDefs(); I < MID.getNumOperands(); I++) {
      auto const &Op = Inst.getOperand(I);
      if (Op.isReg() && Op.getReg().isPhysical()) {
        Result.insert(Op.getReg());
      }
    }

    auto const &ImplicitUses = MID.implicit_uses();
    Result.insert(ImplicitUses.begin(), ImplicitUses.end());
    return deduplicateSubregisters(Result);
  }

  virtual DenseSet<MCRegister>
  getWrittenSuperregisters(MCInst const &Inst) const {
    // Returns the full set of registers that this instruction writes,
    // deduplicated by superregisters. That is, for an instruction that writes
    // both rax and eax, we return {rax}.
    DenseSet<MCRegister> Result;
    auto const &MID = MCII.get(Inst.getOpcode());
    for (unsigned I = 0; I < MID.getNumDefs(); I++) {
      auto const &Op = Inst.getOperand(I);
      if (Op.isReg()) {
        MCRegister const Reg = Op.getReg();
        if (Reg.isPhysical()) {
          Result.insert(Reg);
        }
      }
    }
    auto const &ImplicitDefs = MID.implicit_defs();
    Result.insert(ImplicitDefs.begin(), ImplicitDefs.end());
    return deduplicateSubregisters(Result);
  }

  bool isTaintTracked(MCRegister const Reg) const {
    for (auto const Superreg : getTaintTrackedSuperregisters()) {
      if (MRI.isSubRegisterEq(Superreg, Reg)) {
        return true;
      }
    }
    return false;
  }

  virtual DenseSet<MCRegister>
  getRequiredCleanSuperregisters(MCInst const &Inst) const {
    DenseSet<MCRegister> Result;
    for (auto const &Reg : getReadSuperregisters(Inst)) {
      if (isTaintTracked(Reg)) {
        Result.insert(Reg);
      }
    }

    return deduplicateSubregisters(Result);
  }

  bool isABISymbol(MCSymbol const &Symbol) const {
    return ABISymbolNames.contains(Symbol.getName()) && Symbol.isInSection() &&
           Symbol.getSection().isText() && Symbol.getOffset() == 0;
  }
};

} // namespace llvm

#endif
