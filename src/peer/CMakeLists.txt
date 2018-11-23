add_executable(peer main.c peer.c stdin.c peer-server.c thread_manager.c
		peer-superpeer.c file_manager.c superpeer-peer.c superpeer.c
		keys_cache.c superpeer-superpeer.c)
target_link_libraries(peer PUBLIC fsnp struct slog pthread)
set(MAX_KNOWN_PEER 16)
message(STATUS "MAX_KNOWN_PEER is equal to ${MAX_KNOWN_PEER}")
target_compile_definitions(peer PRIVATE SERVER_PORT=${SERVER_PORT} MAX_KNOWN_PEER=${MAX_KNOWN_PEER})
target_compile_options(peer PRIVATE ${COMMON_COMPILER_FLAGS})