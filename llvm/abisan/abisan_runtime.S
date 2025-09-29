#include "abisan_runtime.h"

.intel_syntax noprefix

.globl __abisan_function_entry
__abisan_function_entry:
    mov r11, qword ptr [rip + __abisan_shadow_stack_pointer]

    // Save stuff into the frame
    mov QWORD PTR [r11 + FRAME_RBX], rbx
    mov QWORD PTR [r11 + FRAME_RBP], rbp
    add rsp, 0x8
    mov QWORD PTR [r11 + FRAME_RSP], rsp
    sub rsp, 0x8
    mov QWORD PTR [r11 + FRAME_R12], r12
    mov QWORD PTR [r11 + FRAME_R13], r13
    mov QWORD PTR [r11 + FRAME_R14], r14
    mov QWORD PTR [r11 + FRAME_R15], r15
    fnstcw [r11 + FRAME_X87CW]
    mov WORD PTR [r11 + FRAME_FS], fs
    stmxcsr DWORD PTR [r11 + FRAME_MXCSR]
    and DWORD PTR [r11 + FRAME_MXCSR], 0xffe0
    // Now that rbx is saved in the shadow stack, we'll be using it as a temporary

    // Save calling function's return address into the frame for later restoration
    mov rbx, QWORD PTR [rsp + 0x8]
    mov QWORD PTR [r11 + FRAME_RETADDR], rbx

    // Save our return address into the frame for debugging purposes
    mov rbx, QWORD PTR [rsp]
    mov QWORD PTR [r11 + FRAME_INSTRUMENTATION_RETADDR], rbx

    // Replace the return address on the stack with abisan_function_exit
    lea rbx, [rip + abisan_function_exit]
    mov QWORD PTR [rsp + 0x8], rbx

    // Update __abisan_shadow_stack_pointer
    mov rbx, QWORD PTR [rip + __abisan_shadow_stack_pointer]
    add rbx, SHADOW_STACK_FRAME_SIZE
    mov QWORD PTR [rip + __abisan_shadow_stack_pointer], rbx

    lea rbx, [rip+__abisan_taint_state]
    mov BYTE PTR [rbx + TAINT_STATE_RAX], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_RBX], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_R10], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_R11], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_R12], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_R13], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_R14], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_R15], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_RBP], 0xff
    mov BYTE PTR [rbx + TAINT_STATE_EFLAGS], 0xff
    // Argument registers should be updated after every call, not here

    // Check for stack alignment
    mov rbx, rsp
    and rbx, 0xf
    cmp rbx, 0x0

    // Put rbx back the way it was
    mov rbx, QWORD PTR [r11 + FRAME_RBX]

    jne stack_misaligned

    ret
stack_misaligned:
    mov rdi, r11
    jmp __abisan_fail_stack_misalignment


abisan_function_exit:
    sub rsp, 0x8 // We never add this back to rsp to make up for the fact that this function is returned into. We'll also use this local space for fnstcw and its ilk

    // Because this is returned into, it's good to clobber anything and everything
    // that a function is allowed to clobber. Also, we use rdi to store the current
    // shadow stack frame because it's the first argument to the __abisan_fail_X functions
    mov rdi, [rip+__abisan_shadow_stack_pointer]
    sub rdi, SHADOW_STACK_FRAME_SIZE
    mov QWORD PTR [rip+__abisan_shadow_stack_pointer], rdi

    fnstcw [rsp]
    mov si, WORD PTR [rsp]
    cmp si, WORD PTR [rdi + FRAME_X87CW]
    jne __abisan_fail_x87cw

    stmxcsr DWORD PTR [rsp]
    mov esi, DWORD PTR [rsp]
    and esi, 0xffe0
    cmp esi, DWORD PTR [rdi + FRAME_MXCSR]
    jne __abisan_fail_mxcsr

    mov si, fs
    cmp si, WORD PTR [rdi + FRAME_FS]
    jne __abisan_fail_fs

    mov rsi, rbx
    cmp rsi, QWORD PTR [rdi + FRAME_RBX]
    jne __abisan_fail_rbx
    
    mov rsi, rbp
    cmp rsi, QWORD PTR [rdi + FRAME_RBP]
    jne __abisan_fail_rbp
    
    mov rsi, rsp
    cmp rsi, QWORD PTR [rdi + FRAME_RSP]
    jne __abisan_fail_rsp
    
    mov rsi, r12
    cmp rsi, QWORD PTR [rdi + FRAME_R12]
    jne __abisan_fail_r12
    
    mov rsi, r13
    cmp rsi, QWORD PTR [rdi + FRAME_R13]
    jne __abisan_fail_r13
    
    mov rsi, r14
    cmp rsi, QWORD PTR [rdi + FRAME_R14]
    jne __abisan_fail_r14
    
    mov rsi, r15
    cmp rsi, QWORD PTR [rdi + FRAME_R15]
    jne __abisan_fail_r15

    // Put the original return address back in place
    mov rdi, QWORD PTR [rdi + FRAME_RETADDR]
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

    // Clobber the red zone
    mov QWORD PTR [rsp - 0x08], rcx
    mov QWORD PTR [rsp - 0x10], rcx
    mov QWORD PTR [rsp - 0x18], rcx
    mov QWORD PTR [rsp - 0x20], rcx
    mov QWORD PTR [rsp - 0x28], rcx
    mov QWORD PTR [rsp - 0x30], rcx
    mov QWORD PTR [rsp - 0x38], rcx
    mov QWORD PTR [rsp - 0x40], rcx
    mov QWORD PTR [rsp - 0x48], rcx
    mov QWORD PTR [rsp - 0x50], rcx
    mov QWORD PTR [rsp - 0x58], rcx
    mov QWORD PTR [rsp - 0x60], rcx
    mov QWORD PTR [rsp - 0x68], rcx
    mov QWORD PTR [rsp - 0x70], rcx
    mov QWORD PTR [rsp - 0x78], rcx
    mov QWORD PTR [rsp - 0x80], rcx

    ret
