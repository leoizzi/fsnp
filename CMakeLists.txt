cmake_minimum_required(VERSION 3.10)
project(fsnp C)

set(CMAKE_C_STANDARD 99)

#set(CMAKE_VERBOSE_MAKEFILE ON)

set(SERVER_PORT 38818 CACHE VALUE "The default listening port of the server")
set(FSNP_TIMEOUT 10000 CACHE VALUE "The standard timeout in milliseconds for reading and writing to sockets.")
set(FSNP_MAX_OWNERS 10 CACHE VALUE "The maximum number of owners in a whohas request")
set(MAX_KNOWN_PEER 16 CACHE VALUE "The maximum number of peers that a superpeer can known. It must be greater or equal to FSNP_MAX_OWNERS")
option(FSNP_MEM_DEBUG "Enable this option if you want to compile for Valgrind" OFF)
option(FSNP_INF_TIMEOUT "If enabled every poll in the fsnp protocol will wait indefinetely" OFF)

include_directories(include)

set(FSNP_GLOBAL_DEF "")

if (NOT SERVER_PORT)
	set(SERVER_PORT 38818)
elseif (SERVER_PORT LESS_EQUAL 0 OR SERVER_PORT GREATER_EQUAL 65535)
	message(FATAL_ERROR "The server port range value is 1-65535. You've passed ${SERVER_PORT}")
endif()

if(CMAKE_BUILD_TYPE MATCHES "Release")
	set(FSNP_INF_TIMEOUT ON)
endif()

if (NOT FSNP_TIMEOUT)
	if (NOT FSNP_INF_TIMEOUT)
		set(FSNP_TIMEOUT 10000)
	else()
		set(FSNP_TIMEOUT -1)
		set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_INF_TIMEOUT)
	endif()
elseif(FSNP_TIMEOUT LESS 0 AND NOT FSNP_INF_TIMEOUT)
	message(FATAL_ERROR "The timeout value must be a positive number")
endif()

if (NOT FSNP_MAX_OWNERS)
	set(FSNP_MAX_OWNERS 10)
endif()

if (NOT MAX_KNOWN_PEER)
	set(MAX_KNOWN_PEER 16)
endif()

if (FSNP_MAX_OWNERS GREATER MAX_KNOWN_PEER)
	message(FATAL_ERROR "FSNP_MAX_OWNERS cannot be greater than MAX_KNOWN_PEER")
endif()

if (FSNP_MEM_DEBUG)
	message(STATUS "Compiling for Valgrind")
	if(APPLE)
		set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_MEM_DEBUG)
	endif()
endif ()

if (FSNP_GSAN)
	message(STATUS "Compiling for Google Sanitizers")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer -g")
endif()

set(COMMON_COMPILER_FLAGS -Wall -Wextra -Wundef -Wshadow -Wcast-align
		-Wno-deprecated -Winline)

# -Wundef: warn if an uninitialized identifier is evaluated in an #if directive.

# -Wshadow: warn whenever a local variable shadows another local variable,
# parameter or global variable or whenever a built-in function is shadowed.

# -Wcast-align: warn whenever a pointer is cast such that the required alignment
# of the target is increased. For example, warn if a char * is cast to an int *
# on machines where integers can only be accessed at two- or four-byte
# boundaries.

if (CMAKE_BUILD_TYPE MATCHES "Debug")
	set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_DEBUG)
	if (NOT FSNP_INF_TIMEOUT)
		set(FSNP_TIMEOUT 65535)
	else()
		set(FSNP_TIMEOUT -1)
		set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_INF_TIMEOUT)
	endif()
endif ()

message(STATUS "Using timeout value of ${FSNP_TIMEOUT} milliseconds")
set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_TIMEOUT=${FSNP_TIMEOUT})

add_definitions(${FSNP_GLOBAL_DEF})

add_subdirectory(src/struct)
add_subdirectory(src/slog)
add_subdirectory(src/fsnp)
add_subdirectory(src/boot_server)
add_subdirectory(src/peer)
add_subdirectory(test/boot_server)
add_subdirectory(test/peer)