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
    sub rsp, 8

    # In the stack
    mov qword ptr [rsp], rbx

    # In the redzone
    mov qword ptr [rsp - 8], rbx

    xor eax, eax
    leave
    ret
