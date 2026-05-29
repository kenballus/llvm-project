# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: not %t 2>&1 | FileCheck %s

# CHECK: ABISanitizer: The DF flag was set at function exit.

.intel_syntax noprefix

.text

.globl main
main:
    pushfq
    or qword ptr [rsp], 0b10000000000
    popfq
    ret
