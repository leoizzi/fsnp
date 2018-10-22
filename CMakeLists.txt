cmake_minimum_required(VERSION 3.10)
project(fsnp C)

set(CMAKE_C_STANDARD 99)

#set(CMAKE_VERBOSE_MAKEFILE ON)

set(SERVER_PORT 38818 CACHE VALUE "The default listening port of the server")
set(FSNP_TIMEOUT 5000 CACHE VALUE "The standard timeout in milliseconds for reading and writing to sockets.")
option(FSNP_MEM_DEBUG "Enable this option if you want to compile for Valgrind" OFF)

include_directories(include)

set(FSNP_GLOBAL_DEF "")

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	message(STATUS "Compiling for a big endian system")
	set(FSNP_GLOBAL_DEF "${FSNP_GLOBAL_DEF} -DFSNP_BIG_ENDIAN")
	else()
	message(STATUS "Compiling for a little endian system")
endif()

if (NOT SERVER_PORT)
	set(SERVER_PORT 38818)
elseif (SERVER_PORT LESS_EQUAL 0 OR SERVER_PORT GREATER_EQUAL 65535)
	message(FATAL_ERROR "The server port range value is 1-65535. You've passed ${SERVER_PORT}")
endif()

if (NOT FSNP_TIMEOUT)
	set(FSNP_TIMEOUT 5000)
elseif(FSNP_TIMEOUT LESS 0)
	message(FATAL_ERROR "The timeout value must be a positive number")
endif()

if (FSNP_MEM_DEBUG)
	message(STATUS "Compiling for Valgrind")
	set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_MEM_DEBUG)
endif ()

set(COMMON_COMPILER_FLAGS -Wall -Wextra -Wundef -Wshadow -Wcast-align
		-Wno-deprecated)

# -Wundef: warn if an uninitialized identifier is evaluated in an #if directive.

# -Wshadow: warn whenever a local variable shadows another local variable,
# parameter or global variable or whenever a built-in function is shadowed.

# -Wcast-align: warn whenever a pointer is cast such that the required alignment
# of the target is increased. For example, warn if a char * is cast to an int *
# on machines where integers can only be accessed at two- or four-byte
# boundaries.

if (CMAKE_BUILD_TYPE MATCHES "Debug")
	set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_DEBUG)
	set(FSNP_TIMEOUT 65535)
endif ()

message(STATUS "Using timeout value of ${FSNP_TIMEOUT} milliseconds")
set(FSNP_GLOBAL_DEF ${FSNP_GLOBAL_DEF} -DFSNP_TIMEOUT=${FSNP_TIMEOUT})

add_definitions(${FSNP_GLOBAL_DEF})

add_subdirectory(src/struct)
add_subdirectory(src/fsnp)
add_subdirectory(src/boot_server)
add_subdirectory(src/peer)
add_subdirectory(test/boot_server)
add_subdirectory(test/peer)