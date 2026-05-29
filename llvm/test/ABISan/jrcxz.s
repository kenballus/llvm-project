# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: %t 2>&1 | count 0

.intel_syntax noprefix

.text

local_function:
    ret

.globl main
main:
    push rbp
    mov rbp, rsp

    mov eax, 1
    xor ecx, ecx
    call local_function # At this point in the static analysis, eax is UNKNOWN, and ebp is CLEAN
    jrcxz 1f # short jump if rcx == 0
    ud2 # fail
    .rept 125 # because we want the max immediate of 127, and ud2 is 2 bytes
    xchg ebp, eax # One byte instruction that requires taint checking
    .endr
1:
    xor eax, eax
    leave
    ret
