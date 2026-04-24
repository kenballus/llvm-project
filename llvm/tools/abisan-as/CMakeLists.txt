set(LLVM_LINK_COMPONENTS
  AllTargetsAsmParsers
  AllTargetsInfos
  AllTargetsDescs
  AllTargetsCodeGens
  MC
  MCParser
  Support
  TargetParser
)

add_llvm_tool(abisan-as
  ABISan.cpp
)

target_compile_options(abisan-as PRIVATE
    -fno-omit-frame-pointer
    -g
    -O0
)

target_include_directories(abisan-as PRIVATE
  ${LLVM_MAIN_SRC_DIR}/lib/Target/X86
  ${LLVM_BINARY_DIR}/lib/Target/X86
)
