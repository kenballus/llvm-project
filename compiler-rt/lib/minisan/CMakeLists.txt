add_compiler_rt_component(minisan)

set(MINISAN_SOURCES
  minisan.cpp
  )

include_directories(..)

set(MINISAN_CFLAGS ${SANITIZER_COMMON_CFLAGS})
set(MINISAN_SUPPORTED_ARCH x86_64)

add_compiler_rt_runtime(clang_rt.minisan
  STATIC
  ARCHS ${MINISAN_SUPPORTED_ARCH}
  SOURCES ${MINISAN_SOURCES}
  OBJECT_LIBS RTSanitizerCommon
              RTSanitizerCommonLibc
              RTSanitizerCommonSymbolizer
  CFLAGS ${MINISAN_CFLAGS}
  PARENT_TARGET minisan)

add_compiler_rt_runtime(clang_rt.minisan
  SHARED
  ARCHS ${MINISAN_SUPPORTED_ARCH}
  SOURCES ${MINISAN_SOURCES}
  OBJECT_LIBS RTSanitizerCommon
              RTSanitizerCommonLibc
              RTSanitizerCommonSymbolizer
  CFLAGS ${MINISAN_CFLAGS}
  PARENT_TARGET minisan)
