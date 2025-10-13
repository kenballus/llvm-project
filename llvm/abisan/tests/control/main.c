#include <stdint.h>

uint64_t test(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9, uint64_t stack_arg);

int main(void) {
    return test(1, 2, 3, 4, 5, 6, 7) != 1 + 2 + 3 + 4 + 5 + 6 + 7;
}
