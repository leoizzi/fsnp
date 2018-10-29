add_library(slog STATIC slog.c)
set(SLOG_COMPILE_OPTIONS ${COMMON_COMPILER_FLAGS} -fPIC)
target_compile_options(slog PUBLIC ${SLOG_COMPILE_OPTIONS})
target_link_libraries(slog pthread)