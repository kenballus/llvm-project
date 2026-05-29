# RUN: abisan-as %s -o %t.o 2>&1 | count 0

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
# RUN: %t 2>&1 | count 0

.intel_syntax noprefix

.global hidden_guy
.hidden hidden_guy
hidden_guy:
    mov rbx, 5 # clobber nv reg
    ret

.global main
main:
    push rbx
    sub rsp, 8 # to misalign stack
    call hidden_guy
    add rsp, 8
    pop rbx
    xor eax, eax
    ret
