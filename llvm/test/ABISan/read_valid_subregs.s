# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: %t 2>&1 | count 0

.intel_syntax noprefix

.text

.globl main
main:
    push rbp
    mov rbp, rsp

    # Write to volatile 64-bit register, read from its sub-regs
    mov rcx, 0x12345678
    mov al, cl
    mov ah, ch
    mov ax, cx
    mov eax, ecx
    mov rax, rcx

    xor eax, eax
    leave
    ret
