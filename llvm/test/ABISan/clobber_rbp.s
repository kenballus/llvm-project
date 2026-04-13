# RUN: abisan %s -o %t.o 2>&1 | FileCheck %s --check-prefix=CHECK-ABISAN

# RUN: clang -static %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
# RUN: not %t 2>&1 | FileCheck %s

# RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -lABISanRuntime
# RUN: export LD_LIBRARY_PATH="%llvm_lib_dir:$LD_LIBRARY_PATH" && not %t 2>&1 | FileCheck %s

# CHECK: ABISanitizer: RBP clobbered with 0x1337

.intel_syntax noprefix

.text

.globl main
main:
# CHECK-ABISAN: [[#@LINE+1]]:5: warning: this instruction might clobber RBP.
    mov ebp, 0x1337
    xor eax, eax
    ret
