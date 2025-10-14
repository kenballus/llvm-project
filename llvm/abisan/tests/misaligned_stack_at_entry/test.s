.intel_syntax noprefix

.global f
f:
    ret

.globl main
main:
    call f
    ret
