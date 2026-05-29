# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: %t 2>&1 | count 0

.intel_syntax noprefix

.text

.globl main
main:
    mov rax, 0
    mov rcx, 256
.Ltop:
    dec rax
    nop # This causes loop to get an immediate of 0x80 (the min)
    .rept 61
    xor edx, edx
    .endr
    loop .Ltop
    ret
