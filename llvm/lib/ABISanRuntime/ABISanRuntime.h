#pragma once
#include <pthread.h> // for pthread_mutex_t
#include <stddef.h>  // for offsetof
#include <stdint.h>  // for uint8_t, uint16_t, uint64_t

#include "llvm/ABISan/AMD64LinuxUserspaceConstants.h"

extern pthread_mutex_t __abisan_mutex;

// The address of the instruction after the last global call in instrumented
// code
extern thread_local void *__abisan_last_instrumented_call_retaddr;

// The return address of the last __abisan_function_exit to run in this thread
extern thread_local void *__abisan_last_instrumented_exit_retaddr;

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
  uint64_t rflags;
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
static_assert(FRAME_RFLAGS == offsetof(struct shadow_stack_frame, rflags));
static_assert(FRAME_INSTRUMENTATION_RETADDR ==
              offsetof(struct shadow_stack_frame, instrumentation_retaddr));
static_assert(FRAME_X87CW == offsetof(struct shadow_stack_frame, x87cw));
static_assert(FRAME_FS == offsetof(struct shadow_stack_frame, fs));
static_assert(FRAME_MXCSR == offsetof(struct shadow_stack_frame, mxcsr));

#define SHADOW_STACK_SIZE (1000)
extern thread_local struct shadow_stack_frame
    __abisan_shadow_stack[SHADOW_STACK_SIZE];
extern thread_local struct shadow_stack_frame *__abisan_shadow_stack_pointer;

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
  uint8_t rflags;
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
static_assert(TAINT_STATE_RFLAGS == offsetof(struct taint_state, rflags));

extern thread_local struct taint_state __abisan_taint_state;

void __abisan_fail_df_set(void);

void __abisan_fail_stack_misalignment(void);

void __abisan_fail_clobber(char const *, uint64_t,
                           struct shadow_stack_frame const *);

void __abisan_taint_fail(char const *);
