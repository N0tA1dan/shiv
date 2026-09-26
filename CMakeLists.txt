cmake_minimum_required(VERSION 3.16)
project(shiv VERSION 0.1.0 DESCRIPTION "A toolkit for hooking functions at a low level" LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

option(SHIV_SANITIZE "Build with AddressSanitizer + UBSan" OFF)
if(SHIV_SANITIZE)
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(shiv_logger STATIC src/logger.cpp)
target_include_directories(shiv_logger PUBLIC include)

# Pick the platform-specific tracee implementation at configure time.
# Only the source for the current OS is compiled; the others are ignored.
if(WIN32)
  set(SHIV_TRACEE_SRC src/tracee_windows.cpp)
elseif(UNIX AND NOT APPLE)
  set(SHIV_TRACEE_SRC src/tracee_linux.cpp)
else()
  message(FATAL_ERROR "shiv: no tracee implementation for this platform yet")
endif()

add_library(shiv_tracee STATIC ${SHIV_TRACEE_SRC})
target_include_directories(shiv_tracee PUBLIC include)
target_link_libraries(shiv_tracee PRIVATE shiv_logger)

add_executable(shiv src/main.cpp)
target_link_libraries(shiv PRIVATE shiv_tracee shiv_logger)
