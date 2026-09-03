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
option(USE_LOCAL_LIBER "Use the libER checkout under libER/libER" ON)

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
    if(USE_LOCAL_LIBER AND EXISTS "${LIBER_LOCAL_SOURCE_DIR}/CMakeLists.txt")
        set(LIBER_SOURCE_DIR "${LIBER_LOCAL_SOURCE_DIR}")
        add_subdirectory(
            "${LIBER_LOCAL_SOURCE_DIR}"
            "${CMAKE_BINARY_DIR}/libER-local")
    else()
        FetchContent_Declare(
            libER
            GIT_REPOSITORY https://github.com/DeveshDFG/libER-1.17.git
            GIT_TAG 22340d9bc8e8ea966f9d1d3872e18908655c6c3d
            GIT_SUBMODULES_RECURSE TRUE
        )
        FetchContent_MakeAvailable(libER)
        set(LIBER_SOURCE_DIR "${liber_SOURCE_DIR}")
    endif()

    set(LIBER_SINGLETONS_CSV "${LIBER_SOURCE_DIR}/symbols/singletons.csv")
    if(NOT EXISTS "${LIBER_SINGLETONS_CSV}")
        message(FATAL_ERROR
            "libER singleton symbols file is missing: ${LIBER_SINGLETONS_CSV}")
    endif()
    file(READ "${LIBER_SINGLETONS_CSV}" LIBER_SINGLETONS_CONTENT)
    string(FIND
        "${LIBER_SINGLETONS_CONTENT}"
        "\"GLOBAL_SoloParamRepository\",\"64511832\""
        LIBER_SOLO_PARAM_REPOSITORY_POSITION)
    if(LIBER_SOLO_PARAM_REPOSITORY_POSITION EQUAL -1)
        message(FATAL_ERROR
            "libER does not contain the Elden Ring 1.17 "
            "GLOBAL_SoloParamRepository symbol (64511832)")
    endif()

    find_package(Python3 COMPONENTS Interpreter REQUIRED)
endif()

if(BUILD_SHARED_DAMAGE_MOD)
    add_library(elden-ring-shared-damage SHARED
        src/dllmain.cpp
        src/hooks.cpp
        src/damage.cpp
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
        PRIVATE libER_static minhook psapi Version)

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
