# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: not %t 2>&1 | FileCheck %s

# CHECK: ABISanitizer: The stack was misaligned at entry to a function!

.intel_syntax noprefix

.text

.global f
f:
    ret

.globl main
main:
    push rbp
    mov rbp, rsp
    sub rsp, 8 // misalign stack
    call f
    leave
    ret
