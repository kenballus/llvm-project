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
    

    ret
stack_misaligned:
    lea rdi, [rip + __abisan_shadow_stack_pointer]
    call __abisan_fail_stack_misalignment // Must be call to realign stack


abisan_function_exit:
    sub rsp, 0x8 // We never add this back to rsp to make up for the fact that this function is returned into. We'll also use this local space for fnstcw and its ilk

    sub qword ptr [rip + __abisan_shadow_stack_pointer], SHADOW_STACK_FRAME_SIZE

    mov r11, qword ptr [rip + __abisan_shadow_stack_pointer]

    fnstcw [rsp]
    mov di, word ptr [rsp]
    cmp di, word ptr [r11 + FRAME_X87CW]
    jne __abisan_fail_x87cw

    stmxcsr dword ptr [rsp]
    mov edi, dword ptr [rsp]
    and edi, 0xffe0
    cmp edi, dword ptr [r11 + FRAME_MXCSR]
    jne __abisan_fail_mxcsr

    mov di, fs
    cmp di, word ptr [r11 + FRAME_FS]
    jne __abisan_fail_fs

    cmp rbx, qword ptr [r11 + FRAME_RBX]
    jne __abisan_fail_rbx
    
    cmp rbp, qword ptr [r11 + FRAME_RBP]
    jne __abisan_fail_rbp
    
    cmp rsp, qword ptr [r11 + FRAME_RSP]
    jne __abisan_fail_rsp
    
    cmp r12, qword ptr [r11 + FRAME_R12]
    jne __abisan_fail_r12
    
    cmp r13, qword ptr [r11 + FRAME_R13]
    jne __abisan_fail_r13
    
    cmp r14, qword ptr [r11 + FRAME_R14]
    jne __abisan_fail_r14
    
    cmp r15, qword ptr [r11 + FRAME_R15]
    jne __abisan_fail_r15

    // Put the original return address back in place
    mov rdi, qword ptr [r11 + FRAME_RETADDR]
    mov [rsp], rdi

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

    // Clobber the red zone
    mov qword ptr [rsp - 0x08], rcx
    mov qword ptr [rsp - 0x10], rcx
    mov qword ptr [rsp - 0x18], rcx
    mov qword ptr [rsp - 0x20], rcx
    mov qword ptr [rsp - 0x28], rcx
    mov qword ptr [rsp - 0x30], rcx
    mov qword ptr [rsp - 0x38], rcx
    mov qword ptr [rsp - 0x40], rcx
    mov qword ptr [rsp - 0x48], rcx
    mov qword ptr [rsp - 0x50], rcx
    mov qword ptr [rsp - 0x58], rcx
    mov qword ptr [rsp - 0x60], rcx
    mov qword ptr [rsp - 0x68], rcx
    mov qword ptr [rsp - 0x70], rcx
    mov qword ptr [rsp - 0x78], rcx
    mov qword ptr [rsp - 0x80], rcx

    ret
