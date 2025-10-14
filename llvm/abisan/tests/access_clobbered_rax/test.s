.intel_syntax noprefix

.global f
f:
    ret

.globl main
main:
    sub rsp, 8
    call f
    add rsp, 8
    mov edi, eax
    ret
