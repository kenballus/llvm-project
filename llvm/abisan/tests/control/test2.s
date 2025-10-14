.intel_syntax noprefix

.global test2
test2:
    mov rdi, 0x414243
    push rdi
    mov rdi, rsp
    call puts
    add rsp, 8
    ret
