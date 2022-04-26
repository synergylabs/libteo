include(FetchContent)

# Command line argument parser library
FetchContent_Declare(
    argparselib
    GIT_REPOSITORY https://github.com/p-ranav/argparse.git
    GIT_TAG        64dd67c7587ec36d1fc39a0f03619ea219968a95 # Snapshot version freeze
)
FetchContent_MakeAvailable(argparselib)

# Formatting library
FetchContent_Declare(
    fmtlib
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        7.1.3
)
FetchContent_MakeAvailable(fmtlib)


FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/zhanghan177/cpp-httplib.git
    GIT_TAG master
)
FetchContent_MakeAvailable(httplib)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/zhanghan177/json.git
  GIT_TAG v3.7.3
)
FetchContent_MakeAvailable(json)


FetchContent_Declare(linenoise
  GIT_REPOSITORY https://github.com/zhanghan177/linenoise-cmake.git
  GIT_TAG 6926db95d25fe4821b4a55c2f915b4c1ec3801ef 
)
FetchContent_MakeAvailable(linenoise)


#####################################
# Compile executables
#####################################

set(TEO_APP_LINKING_LIB 
    fmt::fmt
    argparse
    curl
    linenoise
    nlohmann_json::nlohmann_json
)

add_executable(app app.cpp)
target_compile_features(app PRIVATE cxx_std_17)

target_link_libraries(app PRIVATE teo fmt::fmt argparse stdc++fs)

if (TEO_STORAGE_MODULE)
    add_executable(storage storage.cpp)
    target_compile_features(storage PRIVATE cxx_std_17)

    target_link_libraries(storage PRIVATE teo-storage ${TEO_APP_LINKING_LIB})
endif()

add_executable(device device.cpp)
target_compile_features(device PRIVATE cxx_std_17)

target_link_libraries(device PRIVATE teo ${TEO_APP_LINKING_LIB})


add_executable(admin admin.cpp)
target_compile_features(admin PRIVATE cxx_std_17)

target_link_libraries(admin PRIVATE teo ${TEO_APP_LINKING_LIB})


add_executable(user user.cpp)
target_compile_features(user PRIVATE cxx_std_17)

target_link_libraries(user PRIVATE teo ${TEO_APP_LINKING_LIB})


add_executable(accessor accessor.cpp)
target_compile_features(accessor PRIVATE cxx_std_17)

target_link_libraries(accessor PRIVATE teo ${TEO_APP_LINKING_LIB})


add_executable(device-driver device-driver.cpp)
target_compile_features(device-driver PRIVATE cxx_std_17)

target_link_libraries(device-driver PRIVATE teo ${TEO_APP_LINKING_LIB} httplib)


add_executable(simulate-group simulate-group.cpp)
target_compile_features(simulate-group PRIVATE cxx_std_17)

target_link_libraries(simulate-group PRIVATE teo ${TEO_APP_LINKING_LIB})


# Add meta target to group all clients together
add_custom_target(client-runtime)
add_dependencies(client-runtime device admin user accessor device-driver simulate-group app)
