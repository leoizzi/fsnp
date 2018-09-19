add_library(fsnp SHARED fsnp_tcp_op.c sha-256.c fsnp_init.c fsnp_err.c fsnp_udp_op.c)
target_compile_options(fsnp PUBLIC ${COMMON_COMPILER_FLAGS} -fvisibility=hidden)