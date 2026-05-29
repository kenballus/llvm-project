// RUN: clang -S %s -o %t.s

// RUN: abisan-as %t.s -o %t.o 2>&1 | count 0

// RUN: clang -Wl,-z,now %t.o -o %t -L %llvm_lib_dir -fsanitize=abi
// RUN: not %t -o 2>&1 | FileCheck %s

// CHECK: ABISanitizer: R15 clobbered with 0x1337

#include <pthread.h>

void *test(void *whatever) {
    (void)whatever;
    __asm__ volatile(
        "mov $0x1337, %r15\n"
    );
    return NULL;
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, test, NULL);
    test(NULL);
}
