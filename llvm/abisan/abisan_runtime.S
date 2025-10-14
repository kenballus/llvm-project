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

    // Save our return address into the frame
    mov rbx, qword ptr [rsp] // rbx = our retaddr
    mov qword ptr [r11 + FRAME_INSTRUMENTATION_RETADDR], rbx

    // Save calling function's return address into the frame for later restoration
    mov rbx, qword ptr [rsp + 0x8] // rbx = instrumented function's retaddr
    mov qword ptr [r11 + FRAME_RETADDR], rbx
    mov rbx, qword ptr [r11 + FRAME_RBX] // Put rbx back

    // Replace the return address on the stack with __abisan_function_exit
    lea r11, [rip + __abisan_function_exit] // r11 = __abisan_function_exit
    mov qword ptr [rsp + 0x8], r11

    // If the calling function is instrumented, don't untaint the args, since
    // their taint state is already correct.
    mov r11, qword ptr [rip + __abisan_shadow_stack_pointer]
    mov r11, qword ptr [r11 + FRAME_RETADDR]
    cmp r11, qword ptr [rip + __abisan_last_instrumented_retaddr]

    je done_untainting

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

    // Check if DF is set
    pushfq
    pop r11
    and r11, DF_MASK
    cmp r11, 0
    jne df_set

    // Check for stack misalignment
    mov r11, rsp // r11 = rsp & 0xf
    and r11, 0xf
    cmp r11, 0x0
    jne stack_misaligned

    ret

__abisan_function_exit:
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

    pushfq
    pop rsi
    and rsi, DF_MASK
    cmp rsi, 0
    jne df_set

    // Put the original return address back in place
    mov rsi, qword ptr [rdi + FRAME_RETADDR]
    mov qword ptr [rsp + 8], rsi

    add rsp, 0x8

    // Set every flag, except
    // Res_1 (because defined always to be 1)
    // TF (because too annoying)
    // DF (because disallowed)
    // AC (because too annoying)
    mov r11, 0xffffffff00000000 | 0b11111111111110111111101011111101
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

stack_misaligned:
    lea rdi, [rip + __abisan_shadow_stack_pointer]
    and rsp, -16
    sub rsp, 8
    call __abisan_fail_stack_misalignment

df_set:
    # clear df
    pushfq
    mov r11, DF_MASK
    not r11
    and qword ptr [rsp], r11
    popfq
    and rsp, -16
    sub rsp, 8
    call __abisan_fail_df_set


#define ABISAN_FAIL_CLOBBER_DEF(reg) \
.global __abisan_fail_clobber_##reg ; \
__abisan_fail_clobber_##reg: ; \
    and rsp, -16 ; \
    mov rdx, rdi ; \
    lea rdi, [rip + 1f] ; \
    call __abisan_fail_clobber ; \
1: ; \
    .string #reg

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

#define ABISAN_FAIL_TAINT_DEF(reg) \
.global __abisan_fail_taint_##reg ; \
__abisan_fail_taint_##reg: ; \
    and rsp, -16 ; \
    lea rdi, [rip + 1f] ; \
    call __abisan_fail_taint ; \
1: ; \
    .string #reg

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
