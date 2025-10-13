.intel_syntax noprefix

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

    push rax
    sub rsp, 0x10

    # mov into the stack
    mov QWORD PTR [rsp], rdi

    # mov into the heap
    mov rdi, 1
    call malloc
    mov byte ptr [rax], 0
    mov rdi, rax
    call free

    # Write to volatile 64-bit register, read from its sub-regs
    push rax
    mov rcx, 0x12345678
    mov al, cl
    mov ah, ch
    mov ax, cx
    mov eax, ecx
    mov rax, rcx
    pop rax

    add rsp, 0x10
    pop rax

    ret
