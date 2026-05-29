# I'm not against warning about clobbering rsp, but for now we don't.
# This check is to make sure that no other warnings are emitted.
# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: not %t 2>&1 | FileCheck %s

# CHECK: ABISanitizer: RSP clobbered

.intel_syntax noprefix

.text

.globl main
main:
    mov r8, qword ptr [rsp]
    add rsp, 8
    mov qword ptr [rsp], r8

    xor eax, eax
    ret
