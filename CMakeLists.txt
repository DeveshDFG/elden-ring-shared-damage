cmake_minimum_required(VERSION 3.21)
project(elden-ring-shared-damage CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-D_ITERATOR_DEBUG_LEVEL=0)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

option(BUILD_SHARED_DAMAGE_MOD "Build elden-ring-shared-damage.dll" ON)
option(BUILD_DESTINED_DEATH_MOD "Build elden-ring-destined-death.dll" ON)

include(FetchContent)

if(BUILD_SHARED_DAMAGE_MOD OR BUILD_DESTINED_DEATH_MOD)
    FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG master
    )
    FetchContent_MakeAvailable(minhook)
endif()

if(BUILD_DESTINED_DEATH_MOD)
    set(LIBER_LOCAL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/libER/libER")
    if(EXISTS "${LIBER_LOCAL_SOURCE_DIR}/CMakeLists.txt")
        add_subdirectory(
            "${LIBER_LOCAL_SOURCE_DIR}"
            "${CMAKE_BINARY_DIR}/libER-local")
    else()
        FetchContent_Declare(
            libER
            GIT_REPOSITORY https://github.com/Dasaav-dsv/libER.git
            GIT_TAG d8ae5c92719adca4344d8d902b63286b807f562b
            GIT_SUBMODULES_RECURSE TRUE
        )
        FetchContent_MakeAvailable(libER)
    endif()
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
endif()

if(BUILD_SHARED_DAMAGE_MOD)
    add_library(elden-ring-shared-damage SHARED
        src/dllmain.cpp
        src/hooks.cpp
        src/damage.cpp
        src/shared_damage_boss_diag.cpp
    )

    target_include_directories(elden-ring-shared-damage PRIVATE include)
    target_link_libraries(elden-ring-shared-damage PRIVATE minhook psapi)

    set(
        STEAM_SDK_PATH
        "C:/Steam/steamworks_sdk/sdk"
        CACHE PATH
        "Path to the Steamworks SDK root directory")
    if(STEAM_SDK_PATH)
        target_include_directories(
            elden-ring-shared-damage
            PRIVATE "${STEAM_SDK_PATH}/public")
        target_link_libraries(
            elden-ring-shared-damage
            PRIVATE
            "${STEAM_SDK_PATH}/redistributable_bin/win64/steam_api64.lib")
    else()
        message(FATAL_ERROR "STEAM_SDK_PATH is required for shared damage")
    endif()

    set_target_properties(elden-ring-shared-damage PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/natives"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/natives"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/natives")
endif()

if(BUILD_DESTINED_DEATH_MOD)
    add_library(elden-ring-destined-death SHARED
        src/destined_death_dllmain.cpp
        src/destined_death_hooks.cpp
        src/param_patch.cpp
    )

    target_include_directories(elden-ring-destined-death PRIVATE include)
    target_link_libraries(
        elden-ring-destined-death
        PRIVATE libER_static minhook psapi)

    set_target_properties(elden-ring-destined-death PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/natives"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/natives"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/natives")

    add_custom_command(
        TARGET elden-ring-destined-death PRE_BUILD
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tools/generate_bullet_allowlist.py"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Generating Bullet allowlist")
endif()
