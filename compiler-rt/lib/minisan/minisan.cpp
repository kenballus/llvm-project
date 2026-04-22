//===-- minisan.cpp -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// MiniSanitizer
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_common.h" // for Report, GET_CALLER_PC, GET_CURRENT_FRAME, Die
#include "sanitizer_common/sanitizer_stacktrace.h" // for BufferedStackTrace, UnwindFast, UnwindSlow

using namespace __sanitizer;

__attribute__((constructor(0)))
static void __minisan_init() {
    SetCommonFlagsDefaults();
    InitializeCommonFlags();
}

void BufferedStackTrace::UnwindImpl(uptr pc, uptr, void *, bool, u32 max_depth) {
    UnwindSlow(pc, max_depth);
}

extern "C" {
    void __minisan_crash() {
        Report("ERROR: something bad happened\n");

        BufferedStackTrace stack;
        stack.Unwind(GET_CALLER_PC(), GET_CURRENT_FRAME(), nullptr, /*fast=*/false);
        stack.Print();

        Die();
    }
}
