set(LLVM_LINK_COMPONENTS
  MC
  MCParser
  Support
  TargetParser
  X86CodeGen
  X86Desc
  X86Info
  X86AsmParser
)

add_llvm_tool(abisan
  ABISan.cpp
)

target_compile_options(abisan PRIVATE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -g
    -O0
)

target_link_options(abisan PRIVATE
    -fsanitize=address,undefined
)

target_include_directories(abisan PRIVATE
  ${LLVM_MAIN_SRC_DIR}/lib/Target/X86
  ${LLVM_BINARY_DIR}/lib/Target/X86
)
