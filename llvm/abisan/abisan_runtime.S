#include "abisan_runtime.h"

.intel_syntax noprefix

.globl __abisan_function_entry
__abisan_function_entry:
    mov r11, qword ptr [rip + __abisan_shadow_stack_pointer]
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
    // Requires another register to read the return address into
    mov rbx, qword ptr [rsp + 0x8]
    mov qword ptr [r11 + FRAME_RETADDR], rbx

    // Save our return address into the frame for debugging purposes
    mov rbx, qword ptr [rsp]
    mov qword ptr [r11 + FRAME_INSTRUMENTATION_RETADDR], rbx

    mov rbx, qword ptr [r11 + FRAME_RBX] // Put rbx back

    // Check for stack misalignment
    // Happens here so shadow stack frame is populated
    mov r11, rsp
    and r11, 0xf
    cmp r11, 0x0
    jne stack_misaligned

    // Replace the return address on the stack with abisan_function_exit
    lea r11, [rip + abisan_function_exit]
    mov qword ptr [rsp + 0x8], r11

    // Update __abisan_shadow_stack_pointer
    add qword ptr [rip + __abisan_shadow_stack_pointer], SHADOW_STACK_FRAME_SIZE

    lea r11, [rip + __abisan_taint_state]
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RAX], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RBX], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RCX], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RDX], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RDI], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RSI], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R8], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R9], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R10], 0
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R11], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R12], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R13], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R14], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_R15], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_RBP], 0xff
    mov byte ptr [rip + __abisan_taint_state + TAINT_STATE_EFLAGS], 0xff

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
