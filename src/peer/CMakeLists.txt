add_executable(peer main.c peer.c stdin.c peer-server.c thread_manager.c
		peer-superpeer.c file_manager.c superpeer-peer.c superpeer.c
		keys_cache.c superpeer-superpeer.c)
target_link_libraries(peer PUBLIC fsnp struct)
target_compile_definitions(peer PRIVATE SERVER_PORT=${SERVER_PORT})
target_compile_options(peer PRIVATE ${COMMON_COMPILER_FLAGS})