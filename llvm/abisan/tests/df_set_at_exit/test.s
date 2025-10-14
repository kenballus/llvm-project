.intel_syntax noprefix

.globl main
main:
    pushfq
    or qword ptr [rsp], 0b10000000000
    popfq
    ret
