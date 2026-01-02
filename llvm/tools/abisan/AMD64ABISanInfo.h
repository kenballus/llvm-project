#ifndef LLVM_TOOLS_ABISAN_AMD64ABISANINFO_H
#define LLVM_TOOLS_ABISAN_AMD64ABISANINFO_H

#include "ABISanInfo.h"         // for ABISanInfo
#include "X86InstrInfo.h"       // for X86::* opcode constants
#include "X86RegisterInfo.h"    // for X86::* register constants
#include "llvm/ADT/DenseSet.h"  // for DenseSet
#include "llvm/MC/MCInst.h"     // for MCInst
#include "llvm/MC/MCRegister.h" // for MCRegister
#include <cassert>              // for assert

namespace llvm {

class AMD64ABISanInfo : public ABISanInfo {
private:
  MCRegister findLastRegisterRead(MCInst const &Inst) const {
    // This can't use getReadSuperregisters because it might reorder and dedup.
    auto const &MID = MCII.get(Inst.getOpcode());
    for (int I = MID.getNumOperands() - 1; I >= (int)MID.getNumDefs(); I--) {
      auto const &Op = Inst.getOperand(I);
      if (Op.isReg() && Op.getReg().isPhysical()) {
        return Op.getReg();
      }
    }
    assert(false);
  }

public:
  using ABISanInfo::ABISanInfo;

  bool isSyscall(MCInst const &Inst) const override {
    return Inst.getOpcode() == X86::SYSCALL;
  }

  bool isRet(MCInst const &Inst) const override {
    static DenseSet<unsigned> const RetOpcodes{X86::RET16, X86::RET32,
                                               X86::RET64};
    return RetOpcodes.contains(Inst.getOpcode());
  }

  unsigned getRegisterSize(MCRegister const Reg) const override {
    // For some reason, the generic approach doesn't work for *FLAGS, so it's
    // special-cased here.
    switch (Reg) {
    // Not sure why X86::FLAGS isn't a thing in LLVM
    case X86::EFLAGS:
      return 32;
    case X86::RFLAGS:
      return 64;
    }
    return ABISanInfo::getRegisterSize(Reg);
  }

  DenseSet<MCRegister> const &getSyscallDirtiedSuperregisters() const override {
    static DenseSet<MCRegister> const SyscallDirtiedSuperregisters{X86::RCX,
                                                                   X86::R11};
    return SyscallDirtiedSuperregisters;
  }

  bool unknownsWrittenRegisters(MCInst const &Inst) const override {
    static DenseSet<unsigned> OpcodesThatMakeWrittenRegistersUnknown{
        X86::POPF16, X86::POPF32, X86::POPF64, X86::POP16r,
        X86::POP32r, X86::POP64r, X86::LEAVE,  X86::LEAVE64};
    return OpcodesThatMakeWrittenRegistersUnknown.contains(Inst.getOpcode());
  }

  virtual DenseSet<MCRegister>
  getWrittenSuperregisters(MCInst const &Inst) const override {
    auto Result = ABISanInfo::getWrittenSuperregisters(Inst);

    static DenseSet<MCRegister> const ZeroExtendedRegisters{
        X86::EAX,  X86::EBX,  X86::ECX,  X86::EDX,  X86::EBP,  X86::ESP,
        X86::EDI,  X86::ESI,  X86::R8D,  X86::R9D,  X86::R10D, X86::R11D,
        X86::R12D, X86::R13D, X86::R14D, X86::R15D,
    };

    SmallVector<MCRegister> ToInsert;
    for (auto const Reg : Result) {
      if (ZeroExtendedRegisters.contains(Reg)) {
        ToInsert.push_back(getLargestSuperregister(Reg));
      }
    }
    Result.insert(ToInsert.begin(), ToInsert.end());

    // TODO: Handle CPUID
    return deduplicateSubregisters(Result);
  }

  DenseSet<MCRegister>
  getReadSuperregisters(MCInst const &Inst) const override {
    // TODO: Handle CPUID
    return ABISanInfo::getReadSuperregisters(Inst);
  }

  bool needsTaintCopy(MCInst const &Inst) const override {
    static DenseSet<unsigned> OpcodesThatTriggerTaintCopy{
        X86::MOV8rr,      X86::MOV16rr,     X86::MOV32rr,     X86::MOV64rr,
        X86::MOVZX16rr8,  X86::MOVZX32rr16, X86::MOVZX32rr8,  X86::MOVZX64rr16,
        X86::MOVZX64rr8,  X86::MOVSX16rr32, X86::MOVSX16rr8,  X86::MOVSX32rr16,
        X86::MOVSX32rr32, X86::MOVSX32rr8,  X86::MOVSX64rr16, X86::MOVSX64rr32,
        X86::MOVSX64rr8};

    if (!OpcodesThatTriggerTaintCopy.contains(Inst.getOpcode())) {
      return false;
    }

    auto const ReadSuperregisters = getReadSuperregisters(Inst);
    auto const WrittenSuperregisters = getWrittenSuperregisters(Inst);

    assert(ReadSuperregisters.size() == 1);
    assert(WrittenSuperregisters.size() == 1);
    auto const Src = *ReadSuperregisters.begin();
    auto const Dst = *WrittenSuperregisters.begin();
    return isTaintTracked(Src) && isTaintTracked(Dst);
  }

  DenseSet<MCRegister>
  getRequiredCleanSuperregisters(MCInst const &Inst) const override {
    static DenseSet<unsigned> const OpcodesThatCanUseDirtyData{
        X86::PUSH16i,     X86::PUSH16i8,    X86::PUSH16r,     X86::PUSH16rmm,
        X86::PUSH16rmr,   X86::PUSH2,       X86::PUSH2P,      X86::PUSH32i,
        X86::PUSH32i8,    X86::PUSH32r,     X86::PUSH32rmm,   X86::PUSH32rmr,
        X86::PUSH64i32,   X86::PUSH64i8,    X86::PUSH64r,     X86::PUSH64rmm,
        X86::PUSH64rmr,   X86::PUSHA16,     X86::PUSHA32,     X86::PUSHCS16,
        X86::PUSHCS32,    X86::PUSHDS16,    X86::PUSHDS32,    X86::PUSHES16,
        X86::PUSHES32,    X86::PUSHF16,     X86::PUSHF32,     X86::PUSHF64,
        X86::PUSHFS16,    X86::PUSHFS32,    X86::PUSHFS64,    X86::PUSHGS16,
        X86::PUSHGS32,    X86::PUSHGS64,    X86::PUSHP64r,    X86::PUSHSS16,
        X86::PUSHSS32,    X86::LEAVE,       X86::LEAVE64,     X86::MOV8rr,
        X86::MOV16rr,     X86::MOV32rr,     X86::MOV64rr,     X86::MOVZX16rr8,
        X86::MOVZX32rr16, X86::MOVZX32rr8,  X86::MOVZX64rr16, X86::MOVZX64rr8,
        X86::MOVSX16rr32, X86::MOVSX16rr8,  X86::MOVSX32rr16, X86::MOVSX32rr32,
        X86::MOVSX32rr8,  X86::MOVSX64rr16, X86::MOVSX64rr32, X86::MOVSX64rr8};
    unsigned const Opcode = Inst.getOpcode();
    if (OpcodesThatCanUseDirtyData.contains(Opcode)) {
      return {};
    }

    static DenseSet<unsigned> const RegToRegXorOpcodes{
        X86::XOR8rr,
        X86::XOR16rr,
        X86::XOR32rr,
        X86::XOR64rr,
    };

    if (RegToRegXorOpcodes.contains(Opcode) &&
        getReadSuperregisters(Inst).size() == 1) {
      // xor rxx, rxx
      return {};
    }

    auto Result = ABISanInfo::getRequiredCleanSuperregisters(Inst);

    static DenseSet<unsigned> const RegToMemMovOpcodes{
        // Note: this is incomplete, but I just want to get something working
        X86::MOV8mr, X86::MOV16mr, X86::MOV32mr, X86::MOV64mr};

    if (RegToMemMovOpcodes.contains(Opcode)) {
      // register-to-memory moves are basically like pushes;
      // the register being written out to memory doesn't need
      // to be clean.
      Result.erase(findLastRegisterRead(Inst));
    }
    return Result;
  }
};

} // namespace llvm

#endif
