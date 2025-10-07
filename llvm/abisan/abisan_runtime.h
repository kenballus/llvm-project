#define SHADOW_STACK_FRAME_SIZE 84

// Offsets of fields within struct abisan_shadow_stack_frame
#define FRAME_RETADDR 0x00
#define FRAME_RBX 0x08
#define FRAME_RBP 0x10
#define FRAME_RSP 0x18
#define FRAME_R12 0x20
#define FRAME_R13 0x28
#define FRAME_R14 0x30
#define FRAME_R15 0x38
#define FRAME_INSTRUMENTATION_RETADDR 0x40
#define FRAME_EFLAGS 0x48
#define FRAME_X87CW 0x4c
#define FRAME_FS 0x4e
#define FRAME_MXCSR 0x50

// Offsets of fields within struct abisan_taint_state
#define TAINT_STATE_RAX 0
#define TAINT_STATE_RBX 1
#define TAINT_STATE_RCX 2
#define TAINT_STATE_RDX 3
#define TAINT_STATE_RDI 4
#define TAINT_STATE_RSI 5
#define TAINT_STATE_R8 6
#define TAINT_STATE_R9 7
#define TAINT_STATE_R10 8
#define TAINT_STATE_R11 9
#define TAINT_STATE_R12 10
#define TAINT_STATE_R13 11
#define TAINT_STATE_R14 12
#define TAINT_STATE_R15 13
#define TAINT_STATE_RBP 14
#define TAINT_STATE_EFLAGS 15
