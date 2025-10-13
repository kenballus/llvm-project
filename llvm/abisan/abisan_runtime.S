#include "abisan_runtime.h"

.intel_syntax noprefix

.globl __abisan_function_entry
__abisan_function_entry:
    mov r11, qword ptr [rip + __abisan_shadow_stack_pointer] // r11 = __abisan_shadow_stack_pointer
    // Save stuff into the frame
    mov qword ptr [r11 + FRAME_RBX], rbx
    mov qword ptr [r11 + FRAME_RBP], rbp
    add rsp, 0x8
    mov qword ptr [r11 + FRAME_RSP], rsp
    sub rsp, 0x8
    mov qword ptr [r11 + FRAME_R12], r12
    mov qword ptr [r11 + FRAME_R13], r13
    mov qword ptr [r11 + FRAME_R14], r14
    mov qword ptr [r11 + FRAME_R15], r15
    fnstcw [r11 + FRAME_X87CW]
    mov word ptr [r11 + FRAME_FS], fs
    stmxcsr dword ptr [r11 + FRAME_MXCSR]
    and dword ptr [r11 + FRAME_MXCSR], 0xffe0

    // Save calling function's return address into the frame for later restoration
    mov rbx, qword ptr [rsp + 0x8] // rbx = instrumented function's retaddr
    mov qword ptr [r11 + FRAME_RETADDR], rbx

    // Save our return address into the frame
    mov rbx, qword ptr [rsp] // rbx = our retaddr
    mov qword ptr [r11 + FRAME_INSTRUMENTATION_RETADDR], rbx

    // Replace the return address on the stack with abisan_function_exit
    lea r11, [rip + abisan_function_exit] // r11 = abisan_function_exit
    mov qword ptr [rsp + 0x8], r11

    // If the calling function is instrumented, don't untaint the args, since
    // their taint state is already correct.
    mov r11, qword ptr [rip + __abisan_last_instrumented_call] // r11 = __abisan_last_instrumented_call
    sub rbx, r11 // rbx still contains our retaddr
    cmp rbx, MAX_INSTRUCTION_SIZE
    mov r11, qword ptr [rip + __abisan_shadow_stack_pointer] // r11 = __abisan_shadow_stack_pointer
    mov rbx, qword ptr [r11 + FRAME_RBX] // Put rbx back

    jb done_untainting

    # Untaint all the registers that can be used for arg passing.
    # (This is only done when the calling function is not instrumented)
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RAX], 0 # FP vararg count
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RCX], 0 # Arg 4
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RDX], 0 # Arg 3
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RDI], 0 # Arg 1
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RSI], 0 # Arg 2
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R8], 0  # Arg 5
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R9], 0  # Arg 6
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R10], 0 # Chain pointer

done_untainting:
    // Taint the non-argument registers
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RBX], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R11], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R12], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R13], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R14], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R15], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RBP], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_EFLAGS], 0xff

    // Update __abisan_shadow_stack_pointer
    add qword ptr [rip + __abisan_shadow_stack_pointer], SHADOW_STACK_FRAME_SIZE

    // Check for stack misalignment
    mov r11, rsp // r11 = rsp & 0xf
    and r11, 0xf
    cmp r11, 0x0
    jne stack_misaligned

    ret
stack_misaligned:
    lea rdi, [rip + __abisan_shadow_stack_pointer]
    call __abisan_fail_stack_misalignment // Must be call to realign stack

abisan_function_exit:
    sub rsp, 0x10

    sub qword ptr [rip + __abisan_shadow_stack_pointer], SHADOW_STACK_FRAME_SIZE

    mov rdi, qword ptr [rip + __abisan_shadow_stack_pointer]

    fnstcw [rsp]
    mov si, word ptr [rsp]
    cmp si, word ptr [rdi + FRAME_X87CW]
    jne __abisan_fail_clobber_x87cw

    stmxcsr dword ptr [rsp]
    mov esi, dword ptr [rsp]
    and esi, 0xffe0
    cmp esi, dword ptr [rdi + FRAME_MXCSR]
    jne __abisan_fail_clobber_mxcsr

    mov si, fs
    cmp si, word ptr [rdi + FRAME_FS]
    jne __abisan_fail_clobber_fs

    mov rsi, rbx
    cmp rsi, qword ptr [rdi + FRAME_RBX]
    jne __abisan_fail_clobber_rbx

    mov rsi, rbp
    cmp rsi, qword ptr [rdi + FRAME_RBP]
    jne __abisan_fail_clobber_rbp

    lea rsi, [rsp + 8]
    cmp rsi, qword ptr [rdi + FRAME_RSP]
    jne __abisan_fail_clobber_rsp

    mov rsi, r12
    cmp rsi, qword ptr [rdi + FRAME_R12]
    jne __abisan_fail_clobber_r12

    mov rsi, r13
    cmp rsi, qword ptr [rdi + FRAME_R13]
    jne __abisan_fail_clobber_r13

    mov rsi, r14
    cmp rsi, qword ptr [rdi + FRAME_R14]
    jne __abisan_fail_clobber_r14

    mov rsi, r15
    cmp rsi, qword ptr [rdi + FRAME_R15]
    jne __abisan_fail_clobber_r15

    // Put the original return address back in place
    mov rsi, qword ptr [rdi + FRAME_RETADDR]
    mov qword ptr [rsp + 8], rsi

    add rsp, 8

    // Set every flag, except
    // Res_1 (because defined always to be 1)
    // TF (because too annoying)
    mov r11, 0xfffffffffffffefd
    push r11
    popfq

    // From this point forward, nothing should affect the flags

    // Clobber every register that we're allowed to,
    // except rax and rdx, because they're used for
    // returned values
    mov rcx, 0x4141414141414141
    mov rdi, 0x4141414141414141
    mov rsi, 0x4141414141414141
    mov r8, 0x4141414141414141
    mov r9, 0x4141414141414141
    mov r10, 0x4141414141414141
    mov r11, 0x4141414141414141

    // TODO: clobber the other volatile regs, like the vector regs, mxcsr, x87cw, etc.

    // TODO: clobber the red zone

    ret
