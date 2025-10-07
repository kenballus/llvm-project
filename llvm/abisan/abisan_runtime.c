#include <inttypes.h> // for PRIx16, PRIx64
#include <stddef.h>   // for offsetof
#include <stdint.h>   // for uint8_t, uint16_t, uint64_t
#include <stdio.h>    // for fprintf, stderr
#include <stdlib.h>   // for exit, EXIT_FAILURE

#include "abisan_runtime.h"

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

struct taint_state __abisan_taint_state = {.rax = 0xff,
                                           .rbx = 0xff,
                                           .rcx = 0,
                                           .rdx = 0,
                                           .rdi = 0,
                                           .rsi = 0,
                                           .r8 = 0,
                                           .r9 = 0,
                                           .r10 = 0xff,
                                           .r11 = 0xff,
                                           .r12 = 0xff,
                                           .r13 = 0xff,
                                           .r14 = 0xff,
                                           .r15 = 0xff,
                                           .rbp = 0xff};

#define ABISAN_ERROR_START "\x1b[0;31mABISanitizer: "

[[noreturn]] void
__abisan_fail_stack_misalignment(struct shadow_stack_frame const *const frame) {
  fprintf(stderr,
          ABISAN_ERROR_START
          "The stack was misaligned at entry to the function at address %p, "
          "which was called at address %p.\x1b[0m\n",
          frame->instrumentation_retaddr, frame->retaddr);
  exit(EXIT_FAILURE);
}

[[noreturn]] static void
abisan_fail_clobber(char const *const clobbered_register,
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

#define ABISAN_FAIL_CLOBBER_DEF(reg)                                           \
  [[noreturn]] void __abisan_fail_clobber_##reg(                               \
      struct shadow_stack_frame const *const frame, uint64_t reg) {            \
    abisan_fail_clobber(#reg, reg, frame);                                     \
  }

ABISAN_FAIL_CLOBBER_DEF(rbx)
ABISAN_FAIL_CLOBBER_DEF(rbp)
ABISAN_FAIL_CLOBBER_DEF(rsp)
ABISAN_FAIL_CLOBBER_DEF(r12)
ABISAN_FAIL_CLOBBER_DEF(r13)
ABISAN_FAIL_CLOBBER_DEF(r14)
ABISAN_FAIL_CLOBBER_DEF(r15)
ABISAN_FAIL_CLOBBER_DEF(x87cw)
ABISAN_FAIL_CLOBBER_DEF(fs)
ABISAN_FAIL_CLOBBER_DEF(mxcsr)

[[noreturn]] void __abisan_fail_mov_below_rsp(void) {
  fprintf(stderr,
          ABISAN_ERROR_START "You accessed below the redzone!\x1b[0m\n");
  exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_taint(char const *const r) {
  fprintf(stderr, ABISAN_ERROR_START "You accessed a tainted %s.\x1b[0m\n", r);
  exit(EXIT_FAILURE);
}

#define ABISAN_FAIL_TAINT_DEF(reg)                                             \
  [[noreturn]] void __abisan_fail_taint_##reg(void) { abisan_fail_taint(#reg); }

ABISAN_FAIL_TAINT_DEF(rax)
ABISAN_FAIL_TAINT_DEF(eax)
ABISAN_FAIL_TAINT_DEF(ax)
ABISAN_FAIL_TAINT_DEF(ah)
ABISAN_FAIL_TAINT_DEF(al)

ABISAN_FAIL_TAINT_DEF(rbx)
ABISAN_FAIL_TAINT_DEF(ebx)
ABISAN_FAIL_TAINT_DEF(bx)
ABISAN_FAIL_TAINT_DEF(bh)
ABISAN_FAIL_TAINT_DEF(bl)

ABISAN_FAIL_TAINT_DEF(rcx)
ABISAN_FAIL_TAINT_DEF(ecx)
ABISAN_FAIL_TAINT_DEF(cx)
ABISAN_FAIL_TAINT_DEF(ch)
ABISAN_FAIL_TAINT_DEF(cl)

ABISAN_FAIL_TAINT_DEF(rdx)
ABISAN_FAIL_TAINT_DEF(edx)
ABISAN_FAIL_TAINT_DEF(dx)
ABISAN_FAIL_TAINT_DEF(dh)
ABISAN_FAIL_TAINT_DEF(dl)

ABISAN_FAIL_TAINT_DEF(rdi)
ABISAN_FAIL_TAINT_DEF(edi)
ABISAN_FAIL_TAINT_DEF(di)
ABISAN_FAIL_TAINT_DEF(dil)

ABISAN_FAIL_TAINT_DEF(rsi)
ABISAN_FAIL_TAINT_DEF(esi)
ABISAN_FAIL_TAINT_DEF(si)
ABISAN_FAIL_TAINT_DEF(sil)

ABISAN_FAIL_TAINT_DEF(r8)
ABISAN_FAIL_TAINT_DEF(r8d)
ABISAN_FAIL_TAINT_DEF(r8w)
ABISAN_FAIL_TAINT_DEF(r8b)

ABISAN_FAIL_TAINT_DEF(r9)
ABISAN_FAIL_TAINT_DEF(r9d)
ABISAN_FAIL_TAINT_DEF(r9w)
ABISAN_FAIL_TAINT_DEF(r9b)

ABISAN_FAIL_TAINT_DEF(r10)
ABISAN_FAIL_TAINT_DEF(r10d)
ABISAN_FAIL_TAINT_DEF(r10w)
ABISAN_FAIL_TAINT_DEF(r10b)

ABISAN_FAIL_TAINT_DEF(r11)
ABISAN_FAIL_TAINT_DEF(r11d)
ABISAN_FAIL_TAINT_DEF(r11w)
ABISAN_FAIL_TAINT_DEF(r11b)

ABISAN_FAIL_TAINT_DEF(r12)
ABISAN_FAIL_TAINT_DEF(r12d)
ABISAN_FAIL_TAINT_DEF(r12w)
ABISAN_FAIL_TAINT_DEF(r12b)

ABISAN_FAIL_TAINT_DEF(r13)
ABISAN_FAIL_TAINT_DEF(r13d)
ABISAN_FAIL_TAINT_DEF(r13w)
ABISAN_FAIL_TAINT_DEF(r13b)

ABISAN_FAIL_TAINT_DEF(r14)
ABISAN_FAIL_TAINT_DEF(r14d)
ABISAN_FAIL_TAINT_DEF(r14w)
ABISAN_FAIL_TAINT_DEF(r14b)

ABISAN_FAIL_TAINT_DEF(r15)
ABISAN_FAIL_TAINT_DEF(r15d)
ABISAN_FAIL_TAINT_DEF(r15w)
ABISAN_FAIL_TAINT_DEF(r15b)

ABISAN_FAIL_TAINT_DEF(rbp)
ABISAN_FAIL_TAINT_DEF(ebp)
ABISAN_FAIL_TAINT_DEF(bp)
ABISAN_FAIL_TAINT_DEF(bpl)

ABISAN_FAIL_TAINT_DEF(eflags)
