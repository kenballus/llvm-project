#ifndef LLVM_TOOLS_ABISAN_AMD64LINUXUSERSPACEABISANINSTRUMENTATION_H
#define LLVM_TOOLS_ABISAN_AMD64LINUXUSERSPACEABISANINSTRUMENTATION_H

#include "ABISanInfo.h"                // for ABISanInfo
#include "ABISanInstrumentation.h"     // for ABISanInstrumentation
#include "MCTargetDesc/X86MCAsmInfo.h" // for X86::S_GOTTPOFF, S_None
#include "X86InstrInfo.h"              // for X86::* opcode constants
#include "X86RegisterInfo.h"           // for X86::* register constants
#include "llvm/ADT/SmallVector.h"      // for SmallVector
#include "llvm/ADT/Twine.h"            // for Twine
#include "llvm/MC/MCContext.h"         // for MCContext
#include "llvm/MC/MCExpr.h" // for MCSymbolRefExpr, MCBinaryExpr, MCConstantExpr
#include "llvm/MC/MCInst.h" // for MCInst
#include "llvm/MC/MCInstBuilder.h"  // for MCInstBuilder
#include "llvm/MC/MCRegister.h"     // for MCRegister
#include "llvm/MC/MCSymbol.h"       // for MCSymbol
#include "llvm/Support/SMLoc.h"     // for SMLoc
#include "llvm/Support/SourceMgr.h" // for SourceMgr
#include <cassert>                  // for assert
#include <variant>                  // for std::variant

namespace llvm {

class AMD64LinuxUserspaceABISanInstrumentation : public ABISanInstrumentation {
private:
  MCInst const SaveRedzone;
  MCInst const RestoreRedzone;

  MCSymbol const *CurrentSymbol;

  SmallVector<std::variant<MCInst, MCSymbol *>>
  generateTaintCopy(MCRegister const Src, MCRegister Dst) {
    SmallVector<std::variant<MCInst, MCSymbol *>> Result;
    unsigned DstSize = ABIInfo.getRegisterSize(Dst);
    unsigned SrcSize = ABIInfo.getRegisterSize(Src);
    assert(DstSize >= SrcSize);
    if (DstSize != SrcSize) {
      // If dst is bigger than src, we're looking at an extending move.
      // So clear the destination's taint state, then copy src's into its lower
      // bits.
      Result.append(generateTaintClear(Dst));
      Dst = ABIInfo.getMatchingRegister(Dst, Src);
      assert(Dst != 0);
    }

    Result.push_back(
        MCInstBuilder(X86::CALL64pcrel32)
            .addExpr(MCSymbolRefExpr::create(
                Ctx.getOrCreateSymbol(ABIInfo.getTaintCopySymbolName(Src, Dst)),
                Ctx)));
    return Result;
  }

  SmallVector<std::variant<MCInst, MCSymbol *>>
  generateTaintClear(MCRegister const Reg) {
    return {MCInstBuilder(X86::CALL64pcrel32)
                .addExpr(MCSymbolRefExpr::create(
                    Ctx.getOrCreateSymbol(ABIInfo.getTaintClearSymbolName(Reg)),
                    Ctx))};
  }

  SmallVector<std::variant<MCInst, MCSymbol *>>
  generateTaintSet(MCRegister const Reg) {
    return {MCInstBuilder(X86::CALL64pcrel32)
                .addExpr(MCSymbolRefExpr::create(
                    Ctx.getOrCreateSymbol(ABIInfo.getTaintSetSymbolName(Reg)),
                    Ctx))};
  }

  SmallVector<std::variant<MCInst, MCSymbol *>>
  generateTaintCheck(MCRegister const Reg) {
    return {
        MCInstBuilder(X86::CALL64pcrel32)
            .addExpr(MCSymbolRefExpr::create(
                Ctx.getOrCreateSymbol(ABIInfo.getTaintCheckSymbolName(Reg)),
                Ctx)),
    };
  }

  SmallVector<std::variant<MCInst, MCSymbol *>>
  rewriteInstruction(MCInst const &Inst) {
    SmallVector<std::variant<MCInst, MCSymbol *>> Result;
    if (ABIInfo.isABICall(Inst)) {
      Result.append({
          SaveRedzone,
          MCInstBuilder(X86::PUSH64r).addReg(X86::RAX),
          MCInstBuilder(X86::PUSH64r).addReg(X86::RBX),
          MCInstBuilder(X86::LEA64r)
              .addReg(X86::RBX)
              .addReg(X86::RIP /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addExpr(MCSymbolRefExpr::create(getNextLocalLabel(),
                                               Ctx) /* displacement */)
              .addReg(X86::NoRegister /* segment register */),
          MCInstBuilder(X86::MOV64rm)
              .addReg(X86::RAX)
              .addReg(X86::RIP /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addExpr(MCSymbolRefExpr::create(
                  Ctx.getOrCreateSymbol(
                      "__abisan_last_instrumented_call_retaddr"),
                  X86::S_GOTTPOFF, Ctx) /* displacement */)
              .addReg(X86::NoRegister /* segment register */),
          MCInstBuilder(X86::MOV64mr)
              .addReg(X86::RAX /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addImm(0 /* displacement */)
              .addReg(X86::FS /* segment register */)
              .addReg(X86::RBX),
          MCInstBuilder(X86::POP64r).addReg(X86::RBX),
          MCInstBuilder(X86::POP64r).addReg(X86::RAX),
          RestoreRedzone,
      });
    }

    static DenseSet<unsigned> const JczOpcodes{X86::JRCXZ, X86::JECXZ,
                                               X86::JCXZ};
    static DenseSet<unsigned> const LoopOpcodes{X86::LOOP, X86::LOOPE,
                                                X86::LOOPNE};

    if (JczOpcodes.contains(Inst.getOpcode())) {
      MCRegister RegToTest;
      unsigned TestOpcode;
      switch (Inst.getOpcode()) {
      case X86::JRCXZ:
        RegToTest = X86::RCX;
        TestOpcode = X86::TEST64rr;
        break;
      case X86::JECXZ:
        RegToTest = X86::ECX;
        TestOpcode = X86::TEST32rr;
        break;
      case X86::JCXZ:
        RegToTest = X86::CX;
        TestOpcode = X86::TEST16rr;
        break;
      default:
        assert(false);
      }

      assert(Inst.getNumOperands() == 1);
      auto const &Op = Inst.getOperand(0);
      assert(Op.isExpr());
      auto const &Dst = Op.getExpr();

      Result.append({
          SaveRedzone,
          MCInstBuilder(X86::PUSHF64),
          MCInstBuilder(TestOpcode).addReg(RegToTest).addReg(RegToTest),
          MCInstBuilder(X86::JCC_1)
              .addExpr(MCSymbolRefExpr::create(getNextLocalLabel(), Ctx))
              .addImm(X86::COND_NE),
          MCInstBuilder(X86::POPF64),
          RestoreRedzone,
          MCInstBuilder(X86::JMP_1).addExpr(Dst),
          dispenseLocalLabel(),
          MCInstBuilder(X86::POPF64),
          RestoreRedzone,
      });
    } else if (LoopOpcodes.contains(Inst.getOpcode())) {
      auto const &Op = Inst.getOperand(0);
      assert(Op.isExpr());
      auto const &Dst = Op.getExpr();

      X86::CondCode Cond;
      switch (Inst.getOpcode()) {
      case X86::LOOP:
        Cond = X86::COND_INVALID;
        break;
      case X86::LOOPE:
        Cond = X86::COND_NE; // Inverted deliberately
        break;
      case X86::LOOPNE:
        Cond = X86::COND_E; // Inverted deliberately
        break;
      default:
        assert(false);
      }

      MCRegister const RegToTest =
          Inst.getFlags() & X86::IP_HAS_AD_SIZE ? X86::ECX : X86::RCX;
      unsigned TestOpcode;
      switch (RegToTest) {
      case X86::ECX:
        TestOpcode = X86::TEST32rr;
        break;
      case X86::RCX:
        TestOpcode = X86::TEST64rr;
        break;
      default:
        assert(false);
      }

      Result.append({
          SaveRedzone,
          MCInstBuilder(X86::LEA64r)
              .addReg(X86::RCX)
              .addReg(RegToTest /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addImm(-1 /* displacement */)
              .addReg(X86::NoRegister /* segment register */),
          MCInstBuilder(X86::PUSHF64),
          MCInstBuilder(TestOpcode).addReg(RegToTest).addReg(RegToTest),
          MCInstBuilder(X86::JCC_1)
              .addExpr(MCSymbolRefExpr::create(getNextLocalLabel(), Ctx))
              .addImm(X86::COND_E),
          MCInstBuilder(X86::POPF64),
          MCInstBuilder(X86::PUSHF64),
      });
      if (Cond != X86::COND_INVALID) {
        Result.append(
            {MCInstBuilder(X86::JCC_1)
                 .addExpr(MCSymbolRefExpr::create(getNextLocalLabel(), Ctx))
                 .addImm(Cond)});
      }
      Result.append({MCInstBuilder(X86::POPF64), RestoreRedzone,
                     MCInstBuilder(X86::JMP_1).addExpr(Dst),
                     dispenseLocalLabel(), MCInstBuilder(X86::POPF64),
                     RestoreRedzone});
    } else {
      Result.push_back(Inst);
    }

    // If the return address saved by __abisan_function_exit is the same as
    // the label we just emitted, then don't change the taint state of the
    // return registers. Otherwise, clear them because the called function
    // was uninstrumented.
    if (ABIInfo.isABICall(Inst)) {
      Result.append({
          dispenseLocalLabel(),
          SaveRedzone,
          MCInstBuilder(X86::PUSH64r).addReg(X86::RAX),
          MCInstBuilder(X86::PUSH64r).addReg(X86::RBX),
          MCInstBuilder(X86::LEA64r)
              .addReg(X86::RBX)
              .addReg(X86::RIP /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addExpr(MCSymbolRefExpr::create(getPrevLocalLabel(),
                                               Ctx) /* displacement */)
              .addReg(X86::NoRegister /* segment register */),
          MCInstBuilder(X86::MOV64rm)
              .addReg(X86::RAX)
              .addReg(X86::RIP /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addExpr(MCSymbolRefExpr::create(
                  Ctx.getOrCreateSymbol(
                      "__abisan_last_instrumented_exit_retaddr"),
                  X86::S_GOTTPOFF, Ctx) /* displacement */)
              .addReg(X86::NoRegister /* segment register */),
          MCInstBuilder(X86::CMP64rm)
              .addReg(X86::RBX)
              .addReg(X86::RAX /* base */)
              .addImm(1 /* scale */)
              .addReg(X86::NoRegister /* index */)
              .addImm(0 /* displacement */)
              .addReg(X86::FS /* segment register */),
          MCInstBuilder(X86::POP64r).addReg(X86::RBX),
          MCInstBuilder(X86::POP64r).addReg(X86::RAX),
          RestoreRedzone,
          MCInstBuilder(X86::JCC_1)
              .addExpr(MCSymbolRefExpr::create(getNextLocalLabel(), Ctx))
              .addImm(X86::COND_E),
      });
      bool HaveEmittedTaintUpdate = false;
      for (auto const Reg : ABIInfo.getRetvalSuperregisters()) {
        if (!HaveEmittedTaintUpdate) {
          Result.push_back(SaveRedzone);
          HaveEmittedTaintUpdate = true;
        }
        Result.append(generateTaintClear(Reg));
      }
      if (HaveEmittedTaintUpdate) {
        Result.push_back(RestoreRedzone);
      }
      Result.push_back(dispenseLocalLabel());
    }

    return Result;
  }

public:
  AMD64LinuxUserspaceABISanInstrumentation(MCContext &Ctx,
                                           ABISanInfo const &ABIInfo)
      : ABISanInstrumentation(Ctx, ABIInfo),
        SaveRedzone(MCInstBuilder(X86::LEA64r)
                        .addReg(X86::RSP)
                        .addReg(X86::RSP /* base */)
                        .addImm(1 /* scale */)
                        .addReg(X86::NoRegister /* index */)
                        .addImm(-ABIInfo.getRedzoneSize() /* displacement */)
                        .addReg(X86::NoRegister /* segment register */)),
        RestoreRedzone(MCInstBuilder(X86::LEA64r)
                           .addReg(X86::RSP)
                           .addReg(X86::RSP /* base */)
                           .addImm(1 /* scale */)
                           .addReg(X86::NoRegister /* index */)
                           .addImm(ABIInfo.getRedzoneSize() /* displacement */)
                           .addReg(X86::NoRegister /* segment register */)) {}

  SmallVector<std::variant<MCInst, MCSymbol *>>
  instrumentInstruction(MCInst const &Inst, SMLoc Loc) override {
    SmallVector<std::variant<MCInst, MCSymbol *>> Result;

    // Taint checking
    bool HaveMadeTaintCheck = true;
    for (auto const Superreg : ABIInfo.getRequiredCleanSuperregisters(Inst)) {
      if (getRegisterStatus(Superreg) == ABISanRegisterStatus::Clean) {
        continue;
      }

      // If this register is statically known to be dirty, issue a warning
      if (getRegisterStatus(Superreg) == ABISanRegisterStatus::Dirty) {
        Ctx.reportWarning(Loc, Twine("this instruction might access a "
                                     "clobbered/uninitialized ")
                                   .concat(MRI.getName(Superreg))
                                   .concat("."));
        Ctx.getSourceManager()->PrintMessage(getRegisterStatusSetLoc(Superreg),
                                             SourceMgr::DK_Note,
                                             "marked tainted here:");
      }
      if (HaveMadeTaintCheck) {
        HaveMadeTaintCheck = false;
        Result.push_back(SaveRedzone);
      }
      Result.append(generateTaintCheck(Superreg));
    }
    if (!HaveMadeTaintCheck) {
      Result.push_back(RestoreRedzone);
    }

    Result.append(rewriteInstruction(Inst));

    // Emit taint instructions for each tainted register
    // This needs to happen after the instruction is emitted because it
    // won't work for call otherwise.
    bool HaveSavedRedzone = false;
    for (auto const TaintedReg : ABIInfo.getDirtiedSuperregisters(Inst)) {
      if (getRegisterStatus(TaintedReg) != ABISanRegisterStatus::Dirty) {
        if (!HaveSavedRedzone) {
          HaveSavedRedzone = true;
          Result.push_back(SaveRedzone);
        }
        Result.append(generateTaintSet(TaintedReg));
      }
    }

    for (auto const UntaintedReg : ABIInfo.getCleanedSuperregisters(Inst)) {
      if (ABIInfo.isTaintTracked(UntaintedReg) &&
          getRegisterStatus(UntaintedReg) != ABISanRegisterStatus::Clean) {
        if (!HaveSavedRedzone) {
          HaveSavedRedzone = true;
          Result.push_back(SaveRedzone);
        }
        Result.append(generateTaintClear(UntaintedReg));
      }
    }
    if (ABIInfo.needsTaintCopy(Inst)) {
      if (!HaveSavedRedzone) {
        HaveSavedRedzone = true;
        Result.push_back(SaveRedzone);
      }
      auto const ReadSuperregisters = ABIInfo.getReadSuperregisters(Inst);
      auto const WrittenSuperregisters = ABIInfo.getWrittenSuperregisters(Inst);
      assert(ReadSuperregisters.size() == 1);
      assert(WrittenSuperregisters.size() == 1);
      auto const Src = *ReadSuperregisters.begin();
      auto const Dst = *WrittenSuperregisters.begin();
      Result.append(generateTaintCopy(Src, Dst));
    }
    if (HaveSavedRedzone) { // A register was tainted/taint-cleared/taint-copied
      Result.push_back(RestoreRedzone);
    }

    updateRegisterStatuses(Inst, Loc);

    // If the instruction is a ret, and any nonvolatile register is clean,
    // issue a warning
    if (ABIInfo.isRet(Inst) && CurrentSymbol &&
        ABIInfo.isABISymbol(*CurrentSymbol)) {
      for (auto const NVReg : ABIInfo.getNonvolatileSuperregisters()) {
        for (auto const NVSubreg : MRI.subregs_inclusive(NVReg)) {
          if (getRegisterStatus(NVSubreg) == ABISanRegisterStatus::Clean) {
            Ctx.reportWarning(getRegisterStatusSetLoc(NVSubreg),
                              Twine("this instruction might clobber ")
                                  .concat(MRI.getName(NVSubreg))
                                  .concat("."));
            break;
          }
        }
      }
    }

    return Result;
  }

  SmallVector<std::variant<MCInst, MCSymbol *>>
  instrumentLabel(MCSymbol *Symbol, SMLoc Loc) override {
    if (Symbol->getOffset() == 0) {
      CurrentSymbol = Symbol;
    }

    SmallVector<std::variant<MCInst, MCSymbol *>> Result;
    if (ABIInfo.isABISymbol(*Symbol)) {
      // Taint all of rax except al, which is left in its previous state
      Result.append(
          {MCInstBuilder(X86::CALL64pcrel32)
               .addExpr(MCSymbolRefExpr::create(
                   Ctx.getOrCreateSymbol("__abisan_function_entry"), Ctx)),
           // At this point, it's okay to clobber r11, the flags, and
           // the red zone because none of the instrumented function's
           // code has executed yet.
           // Load our return address into r11
           MCInstBuilder(X86::MOV64rm)
               .addReg(X86::R11)
               .addReg(X86::RIP /* base */)
               .addImm(1 /* scale */)
               .addReg(X86::NoRegister /* index */)
               .addExpr(MCSymbolRefExpr::create(
                   Ctx.getOrCreateSymbol("__abisan_shadow_stack_pointer"),
                   X86::S_GOTTPOFF, Ctx) /* displacement */)
               .addReg(X86::NoRegister /* segment register */),
           MCInstBuilder(X86::MOV64rm)
               .addReg(X86::R11)
               .addReg(X86::R11 /* base */)
               .addImm(1 /* scale */)
               .addReg(X86::NoRegister /* index */)
               .addImm(0 /* displacement */)
               .addReg(X86::FS /* segment register */),
           MCInstBuilder(X86::MOV64rm)
               .addReg(X86::R11)
               .addReg(X86::R11 /* base */)
               .addImm(1 /* scale */)
               .addReg(X86::NoRegister /* index */)
               .addImm(ABIInfo.getShadowStackRetAddrOffset() -
                       ABIInfo.getShadowStackFrameSize() /* displacement */)
               .addReg(X86::NoRegister /* segment register */),
           MCInstBuilder(X86::PUSH64r).addReg(X86::RAX),
           // Load the TLS offset of __abisan_last_instrumented_call_retaddr
           // into rax.
           MCInstBuilder(X86::MOV64rm)
               .addReg(X86::RAX)
               .addReg(X86::RIP /* base */)
               .addImm(1 /* scale */)
               .addReg(X86::NoRegister /* index */)
               .addExpr(MCSymbolRefExpr::create(
                   Ctx.getOrCreateSymbol(
                       "__abisan_last_instrumented_call_retaddr"),
                   X86::S_GOTTPOFF, Ctx) /* displacement */)
               .addReg(X86::NoRegister /* segment register */),
           // Compare the two
           MCInstBuilder(X86::CMP64rm)
               .addReg(X86::R11)
               .addReg(X86::RAX /* base */)
               .addImm(1 /* scale */)
               .addReg(X86::NoRegister /* index */)
               .addImm(0 /* displacement */)
               .addReg(X86::FS /* segment register */),
           // If it's equal, skip untainting the argument
           // registers
           MCInstBuilder(X86::POP64r).addReg(X86::RAX),
           MCInstBuilder(X86::JCC_1)
               .addExpr(MCSymbolRefExpr::create(getNextLocalLabel(), Ctx))
               .addImm(X86::COND_E)});
      Result.push_back(SaveRedzone);
      for (auto const Reg : ABIInfo.getArgumentSuperregisters()) {
        Result.append(generateTaintClear(Reg));
      }
      Result.push_back(RestoreRedzone);
      Result.push_back(dispenseLocalLabel());
    }

    updateRegisterStatuses(*Symbol, Loc);
    return Result;
  }
};

} // namespace llvm

#endif
