#include <inttypes.h>
#include <stdint.h>

#include "abisan.h"
#include "llvm/ABISan/AMD64LinuxUserspaceConstants.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

using namespace __sanitizer;

__attribute__((constructor(0))) static void __abisan_init() {
  SetCommonFlagsDefaults();
  InitializeCommonFlags();
}

void BufferedStackTrace::UnwindImpl(uptr const pc, uptr const bp,
                                    void *const context,
                                    bool const request_fast,
                                    u32 const max_depth) {
  uptr top = 0;
  uptr bottom = 0;
  GetThreadStackTopAndBottom(false, &top, &bottom);
  bool fast = StackTrace::WillUseFastUnwind(request_fast);
  Unwind(max_depth, pc, bp, context, top, bottom, fast);
}

extern "C" {
static void __abisan_die(bool const unwind) {
  BufferedStackTrace stack;
  stack.Unwind(GET_CALLER_PC(), GET_CURRENT_FRAME(), nullptr, /*fast=*/false);
  stack.Print();

  Die();
}

void __abisan_fail_df_set_entry(void) {
  Report("ABISanitizer: The DF flag was set at function entry.\n");

  __abisan_die(true);
}

void __abisan_fail_df_set_exit(void) {
  Report("ABISanitizer: The DF flag was set at function exit.\n");

  __abisan_die(true);
}

void __abisan_fail_stack_misalignment(bool const unwind) {
  Report("ABISanitizer: The stack was misaligned at entry to a function!\n");

  __abisan_die(unwind);
}

void __abisan_fail_clobber(char const *const clobbered_register,
                           uint64_t const old_value,
                           uint64_t const clobbered_value) {
  Report("ABISanitizer: %s clobbered with 0x%" PRIx64 " (expected 0x%" PRIx64
         ")\n",
         clobbered_register, clobbered_value, old_value);
  __abisan_die(true);
}

void __abisan_taint_fail(char const *const r) {
  Report("ABISanitizer: You accessed a tainted %s.\n", r);
  __abisan_die(true);
}
}
