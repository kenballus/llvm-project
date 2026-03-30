#include <inttypes.h> // for PRIx16, PRIx64
#include <pthread.h> // for PTHREAD_MUTEX_INITIALIZER, pthread_mutex_t, pthread_mutex_lock, pthread_mutex_unlock
#include <stddef.h>  // for offsetof
#include <stdint.h>  // for uint8_t, uint16_t, uint64_t
#include <stdio.h>   // for fprintf, stderr

#include "ABISanRuntime.h"
#include "llvm/ABISan/AMD64LinuxUserspaceConstants.h"

pthread_mutex_t __abisan_mutex = PTHREAD_MUTEX_INITIALIZER;

// The address of the instruction after the last global call in instrumented
// code
thread_local void *__abisan_last_instrumented_call_retaddr = NULL;

// The return address of the last __abisan_function_exit to run in this thread
thread_local void *__abisan_last_instrumented_exit_retaddr = NULL;

thread_local struct shadow_stack_frame __abisan_shadow_stack[SHADOW_STACK_SIZE];
thread_local struct shadow_stack_frame *__abisan_shadow_stack_pointer = NULL;

thread_local struct taint_state __abisan_taint_state = {.rax = 0,
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

void __abisan_fail_df_set(void) {
  pthread_mutex_lock(&__abisan_mutex);
  fprintf(stderr, ABISAN_ERROR_START
          "The DF flag was set at function entry/exit.\x1b[0m\n");
  fflush(stderr);
  __asm__ volatile("ud2");
}

void __abisan_fail_stack_misalignment(void) {
  pthread_mutex_lock(&__abisan_mutex);
  fprintf(stderr, ABISAN_ERROR_START
          "The stack was misaligned at entry to a function!\x1b[0m\n");
  fflush(stderr);
  __asm__ volatile("ud2");
}

void __abisan_fail_clobber(char const *const clobbered_register,
                           uint64_t const clobbered_value,
                           struct shadow_stack_frame const *const frame) {
  pthread_mutex_lock(&__abisan_mutex);
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
  fflush(stderr);
  __asm__ volatile("ud2");
}

void __abisan_taint_fail(char const *const r) {
  pthread_mutex_lock(&__abisan_mutex);
  fprintf(stderr, ABISAN_ERROR_START "You accessed a tainted %s.\x1b[0m\n", r);
  fflush(stderr);
  __asm__ volatile("ud2");
}
