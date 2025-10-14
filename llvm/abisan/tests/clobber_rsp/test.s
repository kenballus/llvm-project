.intel_syntax noprefix

.globl test
test:
    mov r11, qword ptr [rsp]
    add rsp, 8
    mov qword ptr [rsp], r11
    ret
