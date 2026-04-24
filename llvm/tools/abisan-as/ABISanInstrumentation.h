#ifndef LLVM_TOOLS_ABISAN_ABISANINSTRUMENTATION_H
#define LLVM_TOOLS_ABISAN_ABISANINSTRUMENTATION_H

// Contains all the mutable state of the pass.
// Should be able to answer questions of the form
// "Is this X in state Y at the current program point?"
// Should also be able to do actions like
// "Set this X to be in state Y starting at the current program point."

#include "ABISanInfo.h"             // for ABISanInfo
#include "llvm/ADT/DenseMap.h"      // for DenseMap
#include "llvm/ADT/SmallVector.h"   // for SmallVector
#include "llvm/ADT/Twine.h"         // for Twine
#include "llvm/MC/MCContext.h"      // for MCContext
#include "llvm/MC/MCInst.h"         // for MCInst
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCRegisterInfo.h" // for MCRegisterInfo
#include "llvm/MC/MCSymbol.h"       // for MCSymbol
#include "llvm/Support/SMLoc.h"     // for SMLoc
#include <cassert>                  // for assert
#include <cstdint>                  // for uint8_t
#include <string>                   // for std::to_string
#include <utility>                  // for std::make_pair
#include <variant>                  // for std::variant

namespace llvm {

enum class ABISanRegisterStatus {
  Dirty,
  Clean,
  Unknown,
};

class ABISanInstrumentation {
private:
  unsigned NumLocalLabels = 0;

protected:
  // Maps each register to its current status, and the location in the program
  // where that status was set.
  DenseMap<MCRegister, std::pair<ABISanRegisterStatus, SMLoc>> Statuses;
  MCContext &Ctx;
  MCRegisterInfo const &MRI;
  ABISanInfo const &ABIInfo;

  void setRegisterStatus(MCRegister const Reg,
                         ABISanRegisterStatus const Status, SMLoc const Loc) {
    Statuses.insert_or_assign(Reg, std::make_pair(Status, Loc));
  }

  void setSuperregisterStatus(MCRegister const Reg,
                              ABISanRegisterStatus const State,
                              SMLoc const Loc) {
    for (auto const Superreg : MRI.superregs_inclusive(Reg)) {
      setRegisterStatus(Superreg, State, Loc);
    }
  }

  void setSubregisterStatus(MCRegister const Reg,
                            ABISanRegisterStatus const State, SMLoc const Loc) {
    for (auto const Subreg : MRI.subregs_inclusive(Reg)) {
      setRegisterStatus(Subreg, State, Loc);
    }
  }

  ABISanRegisterStatus getRegisterStatus(MCRegister const Reg) const {
    return Statuses.at(Reg).first;
  }

  SMLoc getRegisterStatusSetLoc(MCRegister const Reg) const {
    return Statuses.at(Reg).second;
  }

  void setAllRegisterStatuses(ABISanRegisterStatus const Status,
                              SMLoc const Loc) {
    for (auto const Superreg : ABIInfo.getTaintTrackedSuperregisters()) {
      for (auto const Subreg : MRI.subregs_inclusive(Superreg)) {
        setRegisterStatus(Subreg, Status, Loc);
      }
    }
  }

  void updateRegisterStatuses(MCInst const &Inst, SMLoc Loc) {
    // Anything that's taint checked and written to should be marked as
    // clean, unless we're dealing with something like pop, which leaves
    // its written registers in an unknown state.

    // Anything that's required to be clean for this instruction to execute
    // should be marked as clean because if the taint checks succeeded, then
    // this register is okay to access.
    for (auto const Superreg : ABIInfo.getRequiredCleanSuperregisters(Inst)) {
      // Marking a register as clean does not clean its superregisters.
      setSubregisterStatus(Superreg, ABISanRegisterStatus::Clean, Loc);
    }

    for (auto const Superreg : ABIInfo.getCleanedSuperregisters(Inst)) {
      setSubregisterStatus(Superreg, ABISanRegisterStatus::Clean, Loc);
    }

    for (auto const Superreg : ABIInfo.getDirtiedSuperregisters(Inst)) {
      // While technically you could have an instruction that dirties a
      // superregister without dirtying its subregister, this doesn't show up in
      // practice afaik.
      setSuperregisterStatus(Superreg, ABISanRegisterStatus::Dirty, Loc);
      setSubregisterStatus(Superreg, ABISanRegisterStatus::Dirty, Loc);
    }

    for (auto const Superreg : ABIInfo.getUnknownedSuperregisters(Inst)) {
      // Some instructions leave registers in an unknown state (e.g., the
      // retval registers for a call.
      // Marking a register as unknown makes its superregisters unknown.
      setSubregisterStatus(Superreg, ABISanRegisterStatus::Unknown, Loc);
      setSuperregisterStatus(Superreg, ABISanRegisterStatus::Unknown, Loc);
    }

    if (ABIInfo.needsTaintCopy(Inst)) {
      auto const ReadSuperregisters = ABIInfo.getReadSuperregisters(Inst);
      auto const WrittenSuperregisters = ABIInfo.getWrittenSuperregisters(Inst);
      assert(ReadSuperregisters.size() == 1);
      assert(WrittenSuperregisters.size() == 1);
      auto const Src = *ReadSuperregisters.begin();
      auto const Dst = *WrittenSuperregisters.begin();

      assert(ABIInfo.getRegisterSize(Dst) >= ABIInfo.getRegisterSize(Src));
      // Copy the stati of registers with obvious correspondents
      // If any are dirty, then the status of the extended part of the
      // destination (if any) will also be dirty. If any are unknown and none
      // are dirty, then it'll be unknown. Otherwise, clean.
      ABISanRegisterStatus StatusForExtendedRegisters =
          ABISanRegisterStatus::Clean;
      for (auto const SrcSubreg : MRI.subregs_inclusive(Src)) {
        auto const DstSubreg = ABIInfo.getMatchingRegister(Dst, SrcSubreg);
        if (DstSubreg == 0) {
          continue;
        }
        assert(MRI.isSubRegisterEq(Dst, DstSubreg));
        auto const SrcSubregStatus = getRegisterStatus(SrcSubreg);
        switch (SrcSubregStatus) {
        case ABISanRegisterStatus::Clean:
          break;
        case ABISanRegisterStatus::Unknown:
          if (StatusForExtendedRegisters == ABISanRegisterStatus::Clean) {
            // Unknown beats clean
            StatusForExtendedRegisters = ABISanRegisterStatus::Unknown;
          }
          break;
        case ABISanRegisterStatus::Dirty:
          // Dirty beats everything
          StatusForExtendedRegisters = ABISanRegisterStatus::Dirty;
          break;
        }
        setRegisterStatus(DstSubreg, SrcSubregStatus, Loc);
      }

      for (auto const DstSubreg : MRI.subregs_inclusive(Dst)) {
        auto SrcMatch = ABIInfo.getMatchingRegister(Src, DstSubreg);
        if (SrcMatch == 0) {
          // No corresponding register. e.g., looking for ah match in rdi
          // Use state from smallest superregister with a match instead
          auto SmallestMatchingSuper = DstSubreg;
          do {
            SmallestMatchingSuper =
                ABIInfo.getSmallestSuperregister(SmallestMatchingSuper);
            SrcMatch = ABIInfo.getMatchingRegister(Src, SmallestMatchingSuper);
          } while (SrcMatch == 0);
          setRegisterStatus(DstSubreg, getRegisterStatus(SrcMatch), Loc);
        } else if (!MRI.isSubRegisterEq(Src, SrcMatch)) {
          // Corresponding register is out of range indicating
          // (sign|zero)-extension
          setRegisterStatus(DstSubreg, StatusForExtendedRegisters, Loc);
        }
      }
    }
  }

  void updateRegisterStatuses(MCSymbol const &Symbol, SMLoc Loc) {
    if (ABIInfo.isABISymbol(Symbol)) {
      setAllRegisterStatuses(ABISanRegisterStatus::Unknown, Loc);
      for (auto const Reg : ABIInfo.getNonArgumentSubregisters()) {
        setSuperregisterStatus(Reg, ABISanRegisterStatus::Dirty, Loc);
      }
    } else {
      setAllRegisterStatuses(ABISanRegisterStatus::Unknown, Loc);
    }
  }

  MCSymbol *getPrevLocalLabel() {
    assert(NumLocalLabels > 0);
    return Ctx.getOrCreateSymbol(
        Twine(".L__abisan_local_").concat(std::to_string(NumLocalLabels - 1)));
  }

  MCSymbol *getNextLocalLabel() {
    return Ctx.getOrCreateSymbol(
        Twine(".L__abisan_local_").concat(std::to_string(NumLocalLabels)));
  }

  MCSymbol *dispenseLocalLabel() {
    MCSymbol *Result = getNextLocalLabel();
    NumLocalLabels++;
    return Result;
  }

public:
  ABISanInstrumentation(MCContext &Ctx, ABISanInfo const &ABIInfo)
      : Ctx(Ctx), MRI(*(Ctx.getRegisterInfo())), ABIInfo(ABIInfo) {
    setAllRegisterStatuses(ABISanRegisterStatus::Unknown, SMLoc());
  }

  virtual ~ABISanInstrumentation() = default;

  virtual SmallVector<std::variant<MCInst, MCSymbol *>>
  instrumentLabel(MCSymbol *, SMLoc) = 0;

  virtual SmallVector<std::variant<MCInst, MCSymbol *>>
  instrumentInstruction(MCInst const &, SMLoc) = 0;
};

} // namespace llvm

#endif
