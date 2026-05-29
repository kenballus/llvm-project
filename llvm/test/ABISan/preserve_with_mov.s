# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: %t 2>&1 | count 0

.intel_syntax noprefix

.text

.globl main
main:
    mov rdi, rbx
    mov rbx, 1
    mov rbx, rdi
    xor eax, eax
    ret
