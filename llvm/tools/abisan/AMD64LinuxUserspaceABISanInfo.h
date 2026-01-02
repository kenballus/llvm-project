#ifndef LLVM_TOOLS_ABISAN_AMD64LINUXUSERSPACEABISANINFO_H
#define LLVM_TOOLS_ABISAN_AMD64LINUXUSERSPACEABISANINFO_H

#include "AMD64ABISanInfo.h" // for AMD64ABISanInfo
#include "X86InstrInfo.h"    // for X86::* opcode constants
#include "X86RegisterInfo.h" // for X86::* register constants
#include "llvm/ABISan/AMD64LinuxUserspaceConstants.h" // for TAINT_STATE_*, REDZONE_SIZE, SHADOW_STACK_FRAME_SIZE
#include "llvm/ADT/DenseSet.h"  // for DenseSet
#include "llvm/MC/MCInst.h"     // for MCInst
#include "llvm/MC/MCRegister.h" // for MCRegister
#include <cassert>              // for assert
#include <cstdint>              // for uint8_t

namespace llvm {

class AMD64LinuxUserspaceABISanInfo final : public AMD64ABISanInfo {
public:
  using AMD64ABISanInfo::AMD64ABISanInfo;

  unsigned getShadowStackFrameSize() const override {
    return SHADOW_STACK_FRAME_SIZE;
  }

  unsigned getShadowStackRetAddrOffset() const override {
    return FRAME_RETADDR;
  }

  unsigned getRedzoneSize() const override { return REDZONE_SIZE; }

  DenseSet<MCRegister> const &getMainArgumentSuperregisters() const override {
    static DenseSet<MCRegister> const MainArgumentSuperregisters{
        X86::EDI, X86::RSI, X86::RDX};
    return MainArgumentSuperregisters;
  }

  DenseSet<MCRegister> const &getNonArgumentSuperregisters() const override {
    // Superregisters taht are never used for any form of argument passing.
    // Note that RAX is not present because AL is used for argument passing.
    static DenseSet<MCRegister> const NonArgumentSuperregisters{
        X86::RBX, X86::RBP, X86::R11, X86::R12, X86::R13, X86::R14, X86::R15};
    return NonArgumentSuperregisters;
  }

  DenseSet<MCRegister> const &getNonArgumentSubregisters() const override {
    // Registers that are never used for any form of argument passing.
    // We use subregisters here because AL is an argument register.
    static DenseSet<MCRegister> const NonArgumentSubregisters{
        X86::AH,   X86::BL,   X86::BH,   X86::BPL, X86::R11B,
        X86::R12B, X86::R13B, X86::R14B, X86::R15B};
    return NonArgumentSubregisters;
  }

  DenseSet<MCRegister> const &getArgumentSuperregisters() const override {
    // Registers that are used for any form of argument passing
    static DenseSet<MCRegister> const ArgumentSuperregisters{
        X86::AL,  X86::RDI, X86::RSI, X86::RDX,
        X86::RCX, X86::R8,  X86::R9,  X86::R10};
    return ArgumentSuperregisters;
  }

  DenseSet<MCRegister> const &getNonvolatileSuperregisters() const override {
    static DenseSet<MCRegister> const NonvolatileSuperregisters{
        X86::RBP, X86::RBX, X86::R12, X86::R13, X86::R14, X86::R15};
    return NonvolatileSuperregisters;
  }

  DenseSet<MCRegister> const &getTaintTrackedSuperregisters() const override {
    static DenseSet<MCRegister> const TaintTrackedSuperregs{
        X86::RAX, X86::RBX, X86::RCX, X86::RDX,   X86::RDI, X86::RSI,
        X86::R8,  X86::R9,  X86::R10, X86::R11,   X86::R12, X86::R13,
        X86::R14, X86::R15, X86::RBP, X86::RFLAGS};
    return TaintTrackedSuperregs;
  }

  DenseSet<MCRegister> const &getABICallDirtiedSuperregisters() const override {
    static DenseSet<MCRegister> const ABICallDirtiedSuperregisters{
        X86::RDI, X86::RSI, X86::RCX, X86::R8,
        X86::R9,  X86::R10, X86::R11, X86::RFLAGS};

    return ABICallDirtiedSuperregisters;
  }

  DenseSet<MCRegister> const &getRetvalSuperregisters() const override {
    static DenseSet<MCRegister> const RetvalSuperregisters{X86::RAX, X86::RDX};
    return RetvalSuperregisters;
  }

  DenseSet<MCRegister>
  getReadSuperregisters(MCInst const &Inst) const override {
    auto Result = AMD64ABISanInfo::getReadSuperregisters(Inst);
    if (isSyscall(Inst)) {
      // TODO: Handle SYSCALL in a more fine-grained way.
      // This is intentionally eax and not rax.
      static MCRegister const SyscallNrRegister = X86::EAX;
      Result.insert(SyscallNrRegister);
      return deduplicateSubregisters(Result);
    }
    return Result;
  }

  DenseSet<MCRegister>
  getWrittenSuperregisters(MCInst const &Inst) const override {
    auto Result = AMD64ABISanInfo::getWrittenSuperregisters(Inst);
    if (isSyscall(Inst)) {
      // TODO: Handle SYSCALL in a more fine-grained way.
      static MCRegister const SyscallRetvalRegister = X86::RAX;
      Result.insert(SyscallRetvalRegister);
      return deduplicateSubregisters(Result);
    }
    return Result;
  }
};

} // namespace llvm

#endif
