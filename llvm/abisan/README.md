# ABI Sanitizer

ABI Sanitizer (ABISan) is an experimental tool for
0. statically analyzing assembly source code (and not machine code) for ABI violations, and
1. instrumenting assembly source code to check for such ABI violations at runtime.

We can statically detect the following ABI violations:
0. Register clobbering (sound, incomplete)
1. Use of clobbered registers (sound, incomplete)

Neither of these analyses are complete.

We can dynamically detect the following ABI violations:
0. Register clobbering (sound, complete)
1. Use of clobbered registers (sound, complete)
2. Stack misalignment (sound, complete)

## Using ABISan

0. Build llvm.
1. Run `make` in this directory.
2. Run `./abisan code_to_instrument.s > instrumented_code.s`, and observe any warnings.
3. Build the instrumented code as normal and run it.

## Why LLVM?

People keep asking me why this project uses LLVM.
Here's why:
0. LLVM contains all the assembly parsers and serializers I would ever want.
1. LLVM contains an IR that is perfect for working with assembly source code (`MCInst`).
2. LLVM is a actively maintained, and has a nonzero (but still slim) chance of merging this code.

## How it works

### 0. First Pass

Before anything can be done, a first pass is made over the input source code to determine which symbols correspond to functions that should be instrumented.
Currently, a symbol is selected for instrumentation only if it is
0. declared global, and
1. contains instructions.

This is not optimal; some global functions *should* violate the ABI (e.g., `longjmp`), but it works for now.

## Static Analysis

The point of the static analysis is to emit warnings when it is clear that the ABI will be violated without running the input program.

This is achieved by maintaining a set of "clean" registers and a set of "dirty" registers.
Clean registers are registers that can certainly be accessed.
For example, `rax` is clean immediately after executing `mov rax, 1`.

Dirty registers are registers that certainly shouldn't be accessed.
For example, the nonvolatile registers are dirty when a function returns.

Not every register is necessarily clean or dirty at any given program point.
For example, just after a `call` instruction, `rax` is neither dirty nor clean because we don't statically know the type of the function being called.
If it's `void`, `rax` shouldn't be accessed, but if it's non-`void`, it's almost certainly okay to access `rax`.

### Analysis Pass Algorithm

The analysis pass basically works like this:
```
for each statement in the input, reading top to bottom:
    if it's an instruction:
        if it reads from any registers:
            if any of those registers are dirty:
                # note that some instructions are exempted (e.g., push)
                emit a warning indicating that a potentially-clobbered register was accessed
        if it writes to any registers:
            # note that some instructions are exempted (e.g., pop)
            mark those registers as clean
        if it's a call:
            mark as dirty the volatile registers that are never used for return values
            remove from dirty the registers that might be used for return values
        if it's a syscall:
            mark as dirty the registers that are clobbered by syscall (rcx and r11 on amd64)
        if it's a ret:
            if any of the nonvolatile registers are clean:
                emit a warning indicating that a register is likely to be clobbered
    else if it's a label:
        clear the dirty set and the clean set, because this could be a jump target
        if it's one of the functions to be instrumented:
            mark as dirty the registers that are never used for argument passing
            if it's a function with a known signature (like main):
                mark as clean the argument registers it uses
                mark as dirty the argument registers it doesn't use
```

## Dynamic Analysis

The point of the dynamic analysis is to emit errors when the program violates the ABI at runtime.

This is achieved through a small runtime library, complemented by instruction-level instrumentation.
The runtime library provides routines that run at function entry and exit to check for register clobbering and whatnot.
The instrumentation enables register-level taint tracking at runtime.

### Instrumentation Pass Algorithm

The instrumentation pass basically works like this:
```
for each statement in the input, reading top to bottom:
    if it's an instruction:
        if it reads from any registers that aren't statically known to be clean:
            emit code to check if those registers are tainted and crash if so
        if it writes to any registers:
            emit code to mark those registers are not tainted
        emit the instruction
        if it's a call:
            emit code to mark the volatile registers that aren't used for return values as tainted
        if it's a syscall:
            emit code to mark the syscall-clobbered registers as tainted
    if it's a label:
        if it's one of the functions to be instrumented:
            emit a call to __abisan_function_entry
```

### Runtime Library

`__abisan_function_entry` is a special function that is intended to be called as the first instruction in every instrumented function.
It basically saves all nonvolatile registers into a shadow stack, then overwrites the return address of the calling function with the address of `__abisan_function_exit`.
`__abisan_function_exit` checks that the nonvolatile registers' values match those saved in the shadow stack.
Each of these functions also does a bunch of other crap, like checking stack alignedness and updating taint state, but I don't feel like writing more right now.

## Limitations

0. ABISan supports only Linux on AMD64 with the System-V ABI. Eventually, we'd like to support as many architectures as possible.
1. ABISan does not support multithreaded programs due to the use of global state. We're currently seeking an efficient solution to this problem.
2. ABISan does not support binary instrumentation. (WONTFIX)
```
