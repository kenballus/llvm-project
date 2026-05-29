# RUN: abisan-as %s -o %t.o 2>&1 | FileCheck %s --check-prefix=CHECK-ABISAN

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: not %t 2>&1 | FileCheck %s

# CHECK: ABISanitizer: You accessed a tainted R11.

.intel_syntax noprefix

.text

.globl main
main:
    push rbp
    mov rbp, rsp
# CHECK-ABISAN: [[#@LINE+1]]:5: warning: this instruction might access a clobbered/uninitialized R11.
    add rsi, r11
    leave
    ret
