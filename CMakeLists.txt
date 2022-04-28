################################################################################################################
# HEADER Project definition.
################################################################################################################

cmake_minimum_required(VERSION 3.16)
project(teo
    VERSION 1.0.0
    DESCRIPTION "Source code for TEO: Ephemeral Ownership for IoT Devices to Provide Granular Data Control. This is the C++ library and companion apps for demonstrations on Linux machines."
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)

# Create a compile_commands.json file that can be easily parsed by build tools, clang-tidy, etc.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

################################################################################################################
# HEADER Project configuration.
################################################################################################################

option(TEO_EXTENDED_TESTS "Run additional tests" OFF)
option(TEO_STANDALONE_APP "Build standard Linux app (instead of Android native libraries)" ON)
option(TEO_STORAGE_MODULE "Build storage module for third-party storage server" ON)
option(TEO_DEMO_APPS      "Build apps for demonstration" ON)
option(TEO_BLUETOOTH_BEACON "Enable bluetooth beacons for proximity keep-alive" OFF)

# propagates CMake configuration options to the compiler
function(configureProject)
    if (TEO_EXTENDED_TESTS)
        add_definitions(-DTEO_EXTENDED_TESTS)
    endif()
    if (TEO_STANDALONE_APP)
        add_definitions(-DTEO_STANDALONE_APP)
    endif()
    if (TEO_STORAGE_MODULE)
        add_definitions(-DTEO_STORAGE_MODULE)
    endif()
    if (TEO_DEMO_APPS)
        add_definitions(-DTEO_DEMO_APPS)
    endif()
    if (TEO_BLUETOOTH_BEACON)
        add_definitions(-DTEO_BLUETOOTH_BEACON)
    endif()
endfunction()

configureProject()


################################################################################################################
# HEADER System info.
################################################################################################################

message(STATUS "----------------------------------------------------------------------------")
message(STATUS "-- CMake ${CMAKE_VERSION}")
message(STATUS "-- Build ${CMAKE_BUILD_TYPE} / ${CMAKE_SYSTEM_NAME}")
message(STATUS "----------------------------------------------------------------- components")
message(STATUS "-- TEO_EXTENDED_TESTS      Run additional tests                ${TEO_EXTENDED_TESTS}")
message(STATUS "-- TEO_STANDALONE_APP      Build standard Linux app            ${TEO_STANDALONE_APP}")
message(STATUS "                              (instead of Android native libraries)")
message(STATUS "-- TEO_STORAGE_MODULE      Build storage module                ${TEO_STORAGE_MODULE}")
message(STATUS "-- TEO_DEMO_APPS           Build apps for demonstration        ${TEO_DEMO_APPS}")
message(STATUS "-- TEO_BLUETOOTH_BEACON    Enable bluetooth beacons for        ${TEO_BLUETOOTH_BEACON}")
message(STATUS "                              proximity keep-alive ")
message(STATUS "----------------------------------------------------------------------------")

message(STATUS "Compiler: ${CMAKE_CXX_COMPILER} ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "System: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION} ${CMAKE_SYSTEM_PROCESSOR}")

function(print_sys_info QUERY_TARGET)
    cmake_host_system_information(RESULT SYS_INFO QUERY ${QUERY_TARGET})
    message(STATUS "  System ${QUERY_TARGET}: ${SYS_INFO}")
endfunction()
print_sys_info("NUMBER_OF_LOGICAL_CORES;NUMBER_OF_PHYSICAL_CORES")
print_sys_info("HOSTNAME;FQDN")
print_sys_info("AVAILABLE_VIRTUAL_MEMORY;TOTAL_VIRTUAL_MEMORY")
print_sys_info("AVAILABLE_PHYSICAL_MEMORY;TOTAL_PHYSICAL_MEMORY")
print_sys_info("IS_64BIT;HAS_IA64")
print_sys_info("HAS_FPU;HAS_MMX;HAS_MMX_PLUS")
print_sys_info("HAS_SSE;HAS_SSE2;HAS_SSE_FP;HAS_SSE_MMX")
print_sys_info("HAS_AMD_3DNOW;HAS_AMD_3DNOW_PLUS")
print_sys_info("HAS_SERIAL_NUMBER;PROCESSOR_SERIAL_NUMBER")
print_sys_info("PROCESSOR_NAME;PROCESSOR_DESCRIPTION")
print_sys_info("OS_NAME;OS_RELEASE;OS_VERSION;OS_PLATFORM")

message("----------------------------------------------------------------------------")
message("")

# FetchContent added in CMake 3.11, downloads during the configure step
include(FetchContent)

#####################################
# Require libsodium for general crypto
#####################################

# Link: https://github.com/robinlinden/libsodium-cmake

FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/zhanghan177/libsodium-cmake.git
)
set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)

# #####################################
# # Require libdecaf for Ed25519 crypto
# #####################################
# # Sets lib_src_DIR to the path of the target CMake project.
# set(libdecaf_src_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../libs/ed448goldilocks-code)

# # Sets lib_build_DIR to the path of the desired output directory.
# set(libdecaf_build_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../libs/ed448goldilocks-code/build)

# # Adds the outout of the additional CMake build as a prebuilt static
# # library and names it lib_decaf
# add_library(libdecaf STATIC IMPORTED)
# set_target_properties(libdecaf PROPERTIES IMPORTED_LOCATION
#         ${libdecaf_build_DIR}/src/libdecaf.a)
# include_directories(${libdecaf_build_DIR}/src/GENERATED/include)


#####################################
# Require linenoise for demo app IO
#####################################
if (TEO_STANDALONE_APP)
FetchContent_Declare(linenoise
  GIT_REPOSITORY https://github.com/zhanghan177/linenoise-cmake.git
  GIT_TAG 440e89784f1792e3b725be2c2860507f4089bb21 
)
FetchContent_MakeAvailable(linenoise)
endif()

#####################################
# TEO main library
#####################################
# The core library code is here
add_subdirectory(src)

# The executable code for demo apps is here
if (TEO_STANDALONE_APP AND TEO_DEMO_APPS)
    add_subdirectory(apps)
endif()

