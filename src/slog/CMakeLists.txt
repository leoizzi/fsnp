add_library(slog STATIC slog.c)
set(SLOG_COMPILE_OPTIONS ${COMMON_COMPILER_FLAGS})
target_compile_options(slog PUBLIC ${SLOG_COMPILE_OPTIONS})