// RUN: clang -S -I %llvm_include_dir %s -o %t.s

// RUN: abisan %t.s -o %t.o 2>&1 | count 0

// RUN: clang -static %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
// RUN: %t 2>&1 | count 0

// RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
// RUN: export LD_LIBRARY_PATH="%llvm_lib_dir:$LD_LIBRARY_PATH" && %t 2>&1 | count 0

#include "llvm/ABISan/AMD64LinuxUserspaceConstants.h"

#define GET_TLS_ADDR(reg, X) \
    mov reg, qword ptr [rip + X@gottpoff] ; \
    add reg, fs:0

.intel_syntax noprefix

.global main
main:
    GET_TLS_ADDR(rsi, __abisan_taint_state)

    cmp byte ptr [rsi + TAINT_STATE_RFLAGS], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_RAX], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_RBX], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_RCX], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_RDX], 0
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_RDI], 0xf0
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R8], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R9], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R10], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R11], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R12], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R13], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R14], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_R15], 0xff
    je 1f
    ud2
1:
    cmp byte ptr [rsi + TAINT_STATE_RBP], 0xff
    je 1f
    ud2
1:
    xor eax, eax
    ret
