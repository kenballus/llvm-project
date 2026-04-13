set(SOURCES
    ABISanRuntime.c
    ABISanRuntime.S
)

set(CFLAGS
    -g -Wall -Wextra -Wpedantic -Wvla -Wshadow -std=c23 -fPIC
)

add_llvm_library(ABISanRuntime_static STATIC
    ${SOURCES}
)

add_llvm_library(ABISanRuntime_shared SHARED
    ${SOURCES}
)

set_target_properties(ABISanRuntime_static PROPERTIES OUTPUT_NAME ABISanRuntime)
set_target_properties(ABISanRuntime_shared PROPERTIES OUTPUT_NAME ABISanRuntime)

target_compile_options(ABISanRuntime_static PRIVATE ${CFLAGS})
target_compile_options(ABISanRuntime_shared PRIVATE ${CFLAGS})
