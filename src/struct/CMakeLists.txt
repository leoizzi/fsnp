add_library(struct SHARED hashtable.c linklist.c)
set(STRUCT_COMPILE_OPTIONS ${COMMON_COMPILER_FLAGS} -Wno-parentheses -Wno-pointer-sign
		-Wno-unused-function)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
set(STRUCT_COMPILE_OPTIONS ${STRUCT_COMPILE_OPTIONS} -Wno-undefined-inline
		-Wno-unknown-warning-option -Wno-deprecated-declaration)
endif()

target_compile_definitions(struct PUBLIC -DTHREAD_SAFE)
target_compile_options(struct PUBLIC ${STRUCT_COMPILE_OPTIONS})
