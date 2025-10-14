#include <inttypes.h> // for PRIx16, PRIx64
#include <stddef.h>   // for offsetof
#include <stdint.h>   // for uint8_t, uint16_t, uint64_t
#include <stdio.h>    // for fprintf, stderr
#include <stdlib.h>   // for exit, EXIT_FAILURE

#include "abisan_runtime.h"

void *__abisan_last_instrumented_retaddr;

struct shadow_stack_frame {
  void *retaddr;
  uint64_t rbx;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  void *instrumentation_retaddr;
  uint32_t eflags;
  uint16_t x87cw;
  uint16_t fs;
  uint32_t mxcsr;
} __attribute__((packed));

static_assert(SHADOW_STACK_FRAME_SIZE == sizeof(struct shadow_stack_frame));
static_assert(FRAME_RETADDR == offsetof(struct shadow_stack_frame, retaddr));
static_assert(FRAME_RBX == offsetof(struct shadow_stack_frame, rbx));
static_assert(FRAME_RBP == offsetof(struct shadow_stack_frame, rbp));
static_assert(FRAME_RSP == offsetof(struct shadow_stack_frame, rsp));
static_assert(FRAME_R12 == offsetof(struct shadow_stack_frame, r12));
static_assert(FRAME_R13 == offsetof(struct shadow_stack_frame, r13));
static_assert(FRAME_R14 == offsetof(struct shadow_stack_frame, r14));
static_assert(FRAME_R15 == offsetof(struct shadow_stack_frame, r15));
static_assert(FRAME_EFLAGS == offsetof(struct shadow_stack_frame, eflags));
static_assert(FRAME_INSTRUMENTATION_RETADDR ==
              offsetof(struct shadow_stack_frame, instrumentation_retaddr));
static_assert(FRAME_X87CW == offsetof(struct shadow_stack_frame, x87cw));
static_assert(FRAME_FS == offsetof(struct shadow_stack_frame, fs));
static_assert(FRAME_MXCSR == offsetof(struct shadow_stack_frame, mxcsr));

#define SHADOW_STACK_SIZE (1000)
static struct shadow_stack_frame SHADOW_STACK[SHADOW_STACK_SIZE];
#undef SHADOW_STACK_SIZE
struct shadow_stack_frame *__abisan_shadow_stack_pointer = SHADOW_STACK;

struct taint_state {
  uint8_t rax;
  uint8_t rbx;
  uint8_t rcx;
  uint8_t rdx;
  uint8_t rdi;
  uint8_t rsi;
  uint8_t r8;
  uint8_t r9;
  uint8_t r10;
  uint8_t r11;
  uint8_t r12;
  uint8_t r13;
  uint8_t r14;
  uint8_t r15;
  uint8_t rbp;
  uint8_t eflags;
  // TODO: Track all the other registers
} __attribute__((packed));

static_assert(TAINT_STATE_RAX == offsetof(struct taint_state, rax));
static_assert(TAINT_STATE_RBX == offsetof(struct taint_state, rbx));
static_assert(TAINT_STATE_RCX == offsetof(struct taint_state, rcx));
static_assert(TAINT_STATE_RDX == offsetof(struct taint_state, rdx));
static_assert(TAINT_STATE_RSI == offsetof(struct taint_state, rsi));
static_assert(TAINT_STATE_RDI == offsetof(struct taint_state, rdi));
static_assert(TAINT_STATE_R8 == offsetof(struct taint_state, r8));
static_assert(TAINT_STATE_R9 == offsetof(struct taint_state, r9));
static_assert(TAINT_STATE_R10 == offsetof(struct taint_state, r10));
static_assert(TAINT_STATE_R11 == offsetof(struct taint_state, r11));
static_assert(TAINT_STATE_R12 == offsetof(struct taint_state, r12));
static_assert(TAINT_STATE_R13 == offsetof(struct taint_state, r13));
static_assert(TAINT_STATE_R14 == offsetof(struct taint_state, r14));
static_assert(TAINT_STATE_R15 == offsetof(struct taint_state, r15));
static_assert(TAINT_STATE_RBP == offsetof(struct taint_state, rbp));
static_assert(TAINT_STATE_EFLAGS == offsetof(struct taint_state, eflags));

struct taint_state __abisan_taint_state = {.rax = 0,
                                           .rbx = 0,
                                           .rcx = 0,
                                           .rdx = 0,
                                           .rdi = 0,
                                           .rsi = 0,
                                           .r8 = 0,
                                           .r9 = 0,
                                           .r10 = 0,
                                           .r11 = 0,
                                           .r12 = 0,
                                           .r13 = 0,
                                           .r14 = 0,
                                           .r15 = 0,
                                           .rbp = 0};

#define ABISAN_ERROR_START "\x1b[0;31mABISanitizer: "

[[noreturn]] void __abisan_fail_df_set(void) {
  fprintf(stderr, ABISAN_ERROR_START
          "The DF flag was set at function entry/exit.\x1b[0m\n");
  exit(EXIT_FAILURE);
}

[[noreturn]] void
__abisan_fail_stack_misalignment(struct shadow_stack_frame const *const frame) {
  fprintf(stderr,
          ABISAN_ERROR_START
          "The stack was misaligned at entry to the function at address %p, "
          "which was called at address %p.\x1b[0m\n",
          frame->instrumentation_retaddr, frame->retaddr);
  exit(EXIT_FAILURE);
}

[[noreturn]] void
__abisan_fail_clobber(char const *const clobbered_register,
                      uint64_t const clobbered_value,
                      struct shadow_stack_frame const *const frame) {
  fprintf(stderr,
          ABISAN_ERROR_START
          "%s clobbered with 0x%" PRIx64
          " by the function at address %p, which was called at "
          "address %p.\x1b[0m\n",
          clobbered_register, clobbered_value, frame->instrumentation_retaddr,
          frame->retaddr);
  fprintf(stderr, "    Saved rbx: 0x%" PRIx64 "\n", frame->rbx);
  fprintf(stderr, "    Saved rbp: 0x%" PRIx64 "\n", frame->rbp);
  fprintf(stderr, "    Saved rsp: 0x%" PRIx64 "\n", frame->rsp);
  fprintf(stderr, "    Saved r12: 0x%" PRIx64 "\n", frame->r12);
  fprintf(stderr, "    Saved r13: 0x%" PRIx64 "\n", frame->r13);
  fprintf(stderr, "    Saved r14: 0x%" PRIx64 "\n", frame->r14);
  fprintf(stderr, "    Saved r15: 0x%" PRIx64 "\n", frame->r15);
  fprintf(stderr, "    Saved x87 control word: 0x%" PRIx16 "\n", frame->x87cw);
  fprintf(stderr, "    Saved fs: 0x%" PRIx16 "\n", frame->fs);
  exit(EXIT_FAILURE);
}

[[noreturn]] void __abisan_fail_taint(char const *const r) {
  fprintf(stderr, ABISAN_ERROR_START "You accessed a tainted %s.\x1b[0m\n", r);
  exit(EXIT_FAILURE);
}
