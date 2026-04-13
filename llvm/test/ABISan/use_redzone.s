# RUN: abisan %s -o %t.o 2>&1 | count 0

# RUN: clang -static %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
# RUN: %t 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
# RUN: export LD_LIBRARY_PATH="%llvm_lib_dir:$LD_LIBRARY_PATH" && %t 2>&1 | count 0

.intel_syntax noprefix

.text

.globl main
main:
    push rbp
    mov rbp, rsp

    # Write Xs into the red zone
    mov rsi, -1
1:
    cmp rsi, -128
    je 1f
    mov byte ptr [rsp + rsi], 'X'
    dec rsi
    jmp 1b
1:

    # Check that they are still there
    mov rsi, -1
1:
    cmp rsi, -128
    je 1f
    cmp byte ptr [rsp + rsi], 'X'
    jne .Ldie
    dec rsi
    jmp 1b
1:

    xor eax, eax
    leave
    ret

.Ldie:
    mov rax, 60
    mov rdi, 123
    syscall
