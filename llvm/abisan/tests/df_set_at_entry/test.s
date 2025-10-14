.intel_syntax noprefix

.global f
f:
    ret

.globl main
main:
    pushfq
    or qword ptr [rsp], 0b10000000000
    popfq
    sub rsp, 8
    call f

    pushfq
    mov r11, 0b10000000000
    not r11
    and qword ptr [rsp], r11
    popfq
    add rsp, 8
    ret
