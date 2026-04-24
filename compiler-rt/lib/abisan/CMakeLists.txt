add_compiler_rt_component(abisan)

set(ABISAN_SOURCES
  abisan.cpp
  abisan.S
)

include_directories(
  ..
  ../../../llvm/include
)

set(ABISAN_CFLAGS ${SANITIZER_COMMON_CFLAGS})
set(ABISAN_SUPPORTED_ARCH x86_64)

add_compiler_rt_runtime(clang_rt.abisan
  STATIC
  ARCHS ${ABISAN_SUPPORTED_ARCH}
  SOURCES ${ABISAN_SOURCES}
  OBJECT_LIBS RTSanitizerCommon
              RTSanitizerCommonLibc
              RTSanitizerCommonSymbolizer
  CFLAGS ${ABISAN_CFLAGS}
  PARENT_TARGET abisan)

add_compiler_rt_runtime(clang_rt.abisan
  SHARED
  ARCHS ${ABISAN_SUPPORTED_ARCH}
  SOURCES ${ABISAN_SOURCES}
  OBJECT_LIBS RTSanitizerCommon
              RTSanitizerCommonLibc
              RTSanitizerCommonSymbolizer
  CFLAGS ${ABISAN_CFLAGS}
  PARENT_TARGET abisan)
