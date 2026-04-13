# RUN: abisan %s -o %t.o 2>&1 | count 0

# RUN: clang -static %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
# RUN: not %t 2>&1 | FileCheck %s

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
# RUN: export LD_LIBRARY_PATH="%llvm_lib_dir:$LD_LIBRARY_PATH" && not %t 2>&1 | FileCheck %s

# CHECK: ABISanitizer: Access below the red zone attempted!

.intel_syntax noprefix

.globl main
main:
    mov al, BYTE PTR [rsp - 0x81]
    ret
