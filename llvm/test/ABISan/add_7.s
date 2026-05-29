# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: %t 2>&1 | count 0

.intel_syntax noprefix

.text

.globl test
test:
    # Add up the first 7 args into rax
    xor eax, eax
    add rax, rdi
    add rax, rsi
    add rax, rdx
    add rax, rcx
    add rax, r8
    add rax, r9
    add rax, qword ptr [rsp + 8]
    ret

.global main
main:
    mov edi, 1
    mov esi, 2
    mov edx, 3
    mov ecx, 4
    mov r8d, 5
    mov r9d, 6
    mov r10d, 7
    push r10
    call test
    add rsp, 8
    cmp rax, 1 + 2 + 3 + 4 + 5 + 6 + 7
    setne al
    ret
