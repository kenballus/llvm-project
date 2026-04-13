#include "llvm/ABISan/AMD64LinuxUserspaceConstants.h"

.intel_syntax noprefix

.text

#define READ_TLS_QWORD(reg, X) \
    mov reg, qword ptr [rip + X@gottpoff] ; \
    mov reg, qword ptr fs:[reg]

#define GET_TLS_ADDR(reg, X) \
    mov reg, qword ptr [rip + X@gottpoff] ; \
    add reg, fs:0

#define DF_MASK 0b10000000000

.globl __abisan_function_entry
__abisan_function_entry:
    // Check for stack misalignment.
    // This is confusing, because calling __abisan_function_entry is always
    // the first thing an instrumented function does. Thus, we expect rsp % 0xf == 0
    // If it's not, then rsp % 0xf != 8 at entry to the instrumented function, so rsp
    // was misaligned when the instrumented function was called, which violates the ABI.
    mov r11, rsp
    and r11, 0xf
    test r11, r11
    je 1f

    // The stack is misaligned, so align it and fail
    and rsp, -16
    call __abisan_fail_stack_misalignment
1:
    push rbp
    // From this point forward, we know the stack is aligned
    mov rbp, rsp

    // The shadow stack pointer is initialized by this point because of the constructor function defined at the bottom of this file.
    READ_TLS_QWORD(r11, __abisan_shadow_stack_pointer)

    // Save the easy stuff into the frame
    mov [r11 + FRAME_RBX], rbx
    mov [r11 + FRAME_R12], r12
    mov [r11 + FRAME_R13], r13
    mov [r11 + FRAME_R14], r14
    mov [r11 + FRAME_R15], r15
    fnstcw [r11 + FRAME_X87CW]
    mov [r11 + FRAME_FS], fs
    stmxcsr [r11 + FRAME_MXCSR]
    and dword ptr [r11 + FRAME_MXCSR], 0xffe0

    // Save rsp into the frame.
    // Note that the value we want to save in the frame should be the value that was in rsp at 
    // the entry point to the instrumented function. Because this function (__abisan_function_entry)
    // was called, and then we pushed rbp and set rbp = rsp, and this function has no locals,
    // the value we want to save is rbp + 0x10
    mov [r11 + FRAME_RSP], rbp
    add qword ptr [r11 + FRAME_RSP], 0x10

    // Save rbp into the frame.
    // Starting here, rbx is used as scratch
    mov rbx, [rbp]
    mov [r11 + FRAME_RBP], rbx

    // Save our return address into the frame
    mov rbx, [rbp + 0x8] // rbx = our retaddr
    mov [r11 + FRAME_INSTRUMENTATION_RETADDR], rbx

    // Save calling function's return address into the frame for later restoration
    mov rbx, [rbp + 0x10] // rbx = instrumented function's retaddr
    mov [r11 + FRAME_RETADDR], rbx

    // Reset rbx
    mov rbx, [r11 + FRAME_RBX]
    // Starting here, rbx is no longer used as scratch

    // Replace the instrumented function's return address with __abisan_function_exit
    lea r11, [rip + __abisan_function_exit] // r11 = __abisan_function_exit
    mov [rbp + 0x10], r11

    // Update __abisan_shadow_stack_pointer
    GET_TLS_ADDR(r11, __abisan_shadow_stack_pointer)
    add qword ptr [r11], SHADOW_STACK_FRAME_SIZE

    // Taint all non-argument-passing registers
    // Taint all of rax except al, which we leave alone
    GET_TLS_ADDR(r11, __abisan_taint_state)
    or byte ptr [r11 + TAINT_STATE_RAX], 0b11111110
    // Taint rbx, rbp, r10, r11, r12, r13, r14, r15
    mov byte ptr [r11 + TAINT_STATE_RBX], 0xff
    mov byte ptr [r11 + TAINT_STATE_RBP], 0xff
    mov byte ptr [r11 + TAINT_STATE_R10], 0xff
    mov byte ptr [r11 + TAINT_STATE_R11], 0xff
    mov byte ptr [r11 + TAINT_STATE_R12], 0xff
    mov byte ptr [r11 + TAINT_STATE_R13], 0xff
    mov byte ptr [r11 + TAINT_STATE_R14], 0xff
    mov byte ptr [r11 + TAINT_STATE_R15], 0xff
    mov byte ptr [r11 + TAINT_STATE_RFLAGS], 0xff

    // Check if DF is set
    pushfq
    pop r11
    and r11, DF_MASK
    test r11, r11
    je 1f

    // If we're here, df is set, so clear it and fail
    pushfq
    mov r11, DF_MASK
    not r11
    and [rsp], r11
    popfq
    call __abisan_fail_df_set
1:
    leave
    ret

__abisan_function_exit:
    sub rsp, 0x10

    GET_TLS_ADDR(rdi, __abisan_shadow_stack_pointer)
    sub qword ptr [rdi], SHADOW_STACK_FRAME_SIZE

    mov rdi, [rdi]

    lea rsi, [rsp + 8]
    cmp rsi, [rdi + FRAME_RSP]
    je 1f

    and rsp, -16
    call __abisan_fail_clobber_RSP
1:
    // From this point forward, we know the stack is aligned

    fnstcw [rsp]
    mov si, [rsp]
    cmp si, [rdi + FRAME_X87CW]
    je 1f
    call __abisan_fail_clobber_X87CW
1:

    stmxcsr [rsp]
    mov esi, [rsp]
    and esi, 0xffe0
    cmp esi, [rdi + FRAME_MXCSR]
    je 1f
    call __abisan_fail_clobber_MXCSR
1:

    mov si, fs
    cmp si, [rdi + FRAME_FS]
    je 1f
    call __abisan_fail_clobber_FS
1:

    mov rsi, rbx
    cmp rsi, [rdi + FRAME_RBX]
    je 1f
    call __abisan_fail_clobber_RBX
1:

    mov rsi, rbp
    cmp rsi, [rdi + FRAME_RBP]
    je 1f
    call __abisan_fail_clobber_RBP
1:

    mov rsi, r12
    cmp rsi, [rdi + FRAME_R12]
    je 1f
    call __abisan_fail_clobber_R12
1:

    mov rsi, r13
    cmp rsi, [rdi + FRAME_R13]
    je 1f
    call __abisan_fail_clobber_R13
1:

    mov rsi, r14
    cmp rsi, [rdi + FRAME_R14]
    je 1f
    call __abisan_fail_clobber_R14
1:

    mov rsi, r15
    cmp rsi, [rdi + FRAME_R15]
    je 1f
    call __abisan_fail_clobber_R15
1:

    pushfq
    pop rsi
    and rsi, DF_MASK
    test rsi, rsi
    je 1f

    // If we're here, df is set, so clear it and fail
    pushfq
    mov r11, DF_MASK
    not r11
    and [rsp], r11
    popfq
    call __abisan_fail_df_set
1:
    // Put the original return address back in place
    mov rsi, [rdi + FRAME_RETADDR]
    mov [rsp + 8], rsi

    GET_TLS_ADDR(rdi, __abisan_last_instrumented_exit_retaddr)
    mov [rdi], rsi

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

.global __abisan_memory_check
__abisan_memory_check:
    // Expects that the caller saved the redzone and pushed rdi before calling
    // Note that saving rdi in another way is not acceptable; it must be pushed.
    // Checks whether the address in rdi goes below rsp - REDZONE_SIZE,
    // but not so far below that it's fine, like in a heap access.
    // |                 .                   |
    // |                 .                   |
    // |                 .                   |
    // |this                                 |
    // |                is                   |
    // |                                 fine|
    // | - - - - - - - - - - - - - - - - - - | <- rsp
    // |         redzone (also fine)         |
    // | - - - - - - - - - - - - - - - - - - | <- rsp - REDZONE_SIZE
    // |this                                 |
    // |                is                   |
    // |                             not fine|
    // |                 .                   |
    // |                 .                   |
    // |                 .                   |
    // | - - - - - - - - - - - - - - - - - - | <- rsp - STACK_MAX
    // |this                                 |
    // |                is                   |
    // |                                 fine|
    // |                 .                   |
    // |                 .                   |
    // |                 .                   |
    pushfq
    sub rdi, rsp
    sub rdi, 24 # For pushed rdi from caller, return addr, and pushed flags from us
    add rdi, STACK_SIZE
    cmp rdi, STACK_SIZE
    ja 1f
    push rbp
    mov rbp, rsp
    and rsp, -16
    call __abisan_fail_memory_check
1:
    popfq
    ret

#define ABISAN_TAINT_COPY_DEF(dst, src, mask) \
.global __abisan_taint_copy_from_##src##_to_##dst; \
__abisan_taint_copy_from_##src##_to_##dst: ; \
    pushfq ; \
    push rax ; \
    push rbx ; \
    GET_TLS_ADDR(rax, __abisan_taint_state) ; \
    mov bl, byte ptr [rax + TAINT_STATE_##src] ; \
    and bl, mask ; \
    and byte ptr [rax + TAINT_STATE_##dst], ~mask ; \
    or byte ptr [rax + TAINT_STATE_##dst], bl ; \
    pop rbx ; \
    pop rax ; \
    popfq ; \
    ret

#define ABISAN_TAINT_COPY_DEFS(reg, mask) \
.if mask == 1 ; \
    ABISAN_TAINT_COPY_DEF(reg, AL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, BL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, CL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, DL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, DIL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, SIL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, BPL, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R8B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R9B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R10B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R11B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R12B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R13B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R14B, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R15B, mask) ; \
.elseif mask == 2 ; \
    ABISAN_TAINT_COPY_DEF(reg, AH, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, BH, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, CH, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, DH, mask) ; \
.elseif mask == 3 ; \
    ABISAN_TAINT_COPY_DEF(reg, AX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, BX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, CX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, DX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, DI, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, SI, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, BP, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R8W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R9W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R10W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R11W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R12W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R13W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R14W, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R15W, mask) ; \
.elseif mask == 15 ; \
    ABISAN_TAINT_COPY_DEF(reg, EAX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, EBX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, ECX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, EDX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, EDI, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, ESI, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, EBP, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R8D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R9D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R10D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R11D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R12D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R13D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R14D, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R15D, mask) ; \
.elseif mask == 255 ; \
    ABISAN_TAINT_COPY_DEF(reg, RAX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, RBX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, RCX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, RDX, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, RDI, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, RSI, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, RBP, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R8, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R9, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R10, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R11, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R12, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R13, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R14, mask) ; \
    ABISAN_TAINT_COPY_DEF(reg, R15, mask) ; \
.endif

// Note: we don't save the redzone in any of these because
// call will clobber the redzone on its own. Thus, we expect
// the caller to have already saved the redzone.
#define ABISAN_TAINT_DEF(reg, mask) \
.global __abisan_taint_set_##reg ; \
__abisan_taint_set_##reg: ; \
    pushfq ; \
    push rax ; \
    GET_TLS_ADDR(rax, __abisan_taint_state) ; \
    or byte ptr [rax + TAINT_STATE_##reg], mask ; \
    pop rax ; \
    popfq ; \
    ret ; \
.global __abisan_taint_clear_##reg ; \
__abisan_taint_clear_##reg: ; \
    pushfq ; \
    push rax ; \
    GET_TLS_ADDR(rax, __abisan_taint_state) ; \
    and byte ptr [rax + TAINT_STATE_##reg], ~mask ; \
    pop rax ; \
    popfq ; \
    ret ; \
.global __abisan_taint_check_##reg ; \
__abisan_taint_check_##reg: ; \
    push rax ; \
    GET_TLS_ADDR(rax, __abisan_taint_state) ; \
    mov al, byte ptr [rax + TAINT_STATE_##reg] ; \
    and al, mask ; \
    test al, al ; \
    je 1f ; \
    push rbp ; \
    mov rbp, rsp ; \
    and rsp, -16 ; \
    lea rdi, [rip + .Lstr_##reg] ; \
    call __abisan_taint_fail ; \
1: ; \
    pop rax ; \
    ret ; \
.Lstr_##reg: ; \
    .string #reg ; \
ABISAN_TAINT_COPY_DEFS(reg, mask)


#define ABISAN_TAINT8LO_DEF(reg) ABISAN_TAINT_DEF(reg, 1)
#define ABISAN_TAINT8HI_DEF(reg) ABISAN_TAINT_DEF(reg, 2)
#define ABISAN_TAINT16_DEF(reg) ABISAN_TAINT_DEF(reg, 3)
#define ABISAN_TAINT32_DEF(reg) ABISAN_TAINT_DEF(reg, 15)
#define ABISAN_TAINT64_DEF(reg) ABISAN_TAINT_DEF(reg, 255)

ABISAN_TAINT8LO_DEF(AL)
ABISAN_TAINT8LO_DEF(BL)
ABISAN_TAINT8LO_DEF(CL)
ABISAN_TAINT8LO_DEF(DL)
ABISAN_TAINT8LO_DEF(DIL)
ABISAN_TAINT8LO_DEF(SIL)
ABISAN_TAINT8LO_DEF(BPL)
ABISAN_TAINT8LO_DEF(R8B)
ABISAN_TAINT8LO_DEF(R9B)
ABISAN_TAINT8LO_DEF(R10B)
ABISAN_TAINT8LO_DEF(R11B)
ABISAN_TAINT8LO_DEF(R12B)
ABISAN_TAINT8LO_DEF(R13B)
ABISAN_TAINT8LO_DEF(R14B)
ABISAN_TAINT8LO_DEF(R15B)

ABISAN_TAINT8HI_DEF(AH)
ABISAN_TAINT8HI_DEF(BH)
ABISAN_TAINT8HI_DEF(CH)
ABISAN_TAINT8HI_DEF(DH)

ABISAN_TAINT16_DEF(AX)
ABISAN_TAINT16_DEF(BX)
ABISAN_TAINT16_DEF(CX)
ABISAN_TAINT16_DEF(DX)
ABISAN_TAINT16_DEF(DI)
ABISAN_TAINT16_DEF(SI)
ABISAN_TAINT16_DEF(BP)
ABISAN_TAINT16_DEF(R8W)
ABISAN_TAINT16_DEF(R9W)
ABISAN_TAINT16_DEF(R10W)
ABISAN_TAINT16_DEF(R11W)
ABISAN_TAINT16_DEF(R12W)
ABISAN_TAINT16_DEF(R13W)
ABISAN_TAINT16_DEF(R14W)
ABISAN_TAINT16_DEF(R15W)
ABISAN_TAINT16_DEF(FLAGS)

ABISAN_TAINT32_DEF(EAX)
ABISAN_TAINT32_DEF(EBX)
ABISAN_TAINT32_DEF(ECX)
ABISAN_TAINT32_DEF(EDX)
ABISAN_TAINT32_DEF(EDI)
ABISAN_TAINT32_DEF(ESI)
ABISAN_TAINT32_DEF(EBP)
ABISAN_TAINT32_DEF(R8D)
ABISAN_TAINT32_DEF(R9D)
ABISAN_TAINT32_DEF(R10D)
ABISAN_TAINT32_DEF(R11D)
ABISAN_TAINT32_DEF(R12D)
ABISAN_TAINT32_DEF(R13D)
ABISAN_TAINT32_DEF(R14D)
ABISAN_TAINT32_DEF(R15D)
ABISAN_TAINT32_DEF(EFLAGS)

ABISAN_TAINT64_DEF(RAX)
ABISAN_TAINT64_DEF(RBX)
ABISAN_TAINT64_DEF(RCX)
ABISAN_TAINT64_DEF(RDX)
ABISAN_TAINT64_DEF(RDI)
ABISAN_TAINT64_DEF(RSI)
ABISAN_TAINT64_DEF(RBP)
ABISAN_TAINT64_DEF(R8)
ABISAN_TAINT64_DEF(R9)
ABISAN_TAINT64_DEF(R10)
ABISAN_TAINT64_DEF(R11)
ABISAN_TAINT64_DEF(R12)
ABISAN_TAINT64_DEF(R13)
ABISAN_TAINT64_DEF(R14)
ABISAN_TAINT64_DEF(R15)
ABISAN_TAINT64_DEF(RFLAGS)

#define ABISAN_FAIL_CLOBBER_DEF(reg) \
.global __abisan_fail_clobber_##reg ; \
__abisan_fail_clobber_##reg: ; \
    push rbp ; \
    mov rbp, rsp ; \
    and rsp, -16 ; \
    mov rdx, rdi ; \
    lea rdi, [rip + 1f] ; \
    call __abisan_fail_clobber ; \
1: ; \
    .string #reg

ABISAN_FAIL_CLOBBER_DEF(RBX)
ABISAN_FAIL_CLOBBER_DEF(RBP)
ABISAN_FAIL_CLOBBER_DEF(RSP)
ABISAN_FAIL_CLOBBER_DEF(R12)
ABISAN_FAIL_CLOBBER_DEF(R13)
ABISAN_FAIL_CLOBBER_DEF(R14)
ABISAN_FAIL_CLOBBER_DEF(R15)
ABISAN_FAIL_CLOBBER_DEF(X87CW)
ABISAN_FAIL_CLOBBER_DEF(FS)
ABISAN_FAIL_CLOBBER_DEF(MXCSR)

__abisan_initialize_shadow_stack_pointer:
    push rbp
    mov rbp, rsp

    GET_TLS_ADDR(rdi, __abisan_shadow_stack_pointer)
    GET_TLS_ADDR(rsi, __abisan_shadow_stack)
    mov [rdi], rsi

    leave
    ret

.section .init_array.101
.align 8
.quad __abisan_initialize_shadow_stack_pointer
