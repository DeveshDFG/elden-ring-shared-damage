cmake_minimum_required(VERSION 3.21)
project(elden-ring-shared-damage C CXX)  # C required to compile ini.c

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use MSVC /MD (dynamic CRT) to match the game's runtime
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

include(FetchContent)

FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(minhook)

# inih — populate only (no FetchContent_MakeAvailable) so their CMakeLists is
# not invoked. ini.c is added directly to our target as a single source file.
FetchContent_Declare(
    inih
    GIT_REPOSITORY https://github.com/benhoyt/inih.git
    GIT_TAG        master
)
FetchContent_GetProperties(inih)
if(NOT inih_POPULATED)
    FetchContent_Populate(inih)
endif()

add_library(elden-ring-shared-damage SHARED
    src/dllmain.cpp
    src/hooks.cpp
    src/damage.cpp
    ${inih_SOURCE_DIR}/ini.c
)

target_include_directories(elden-ring-shared-damage PRIVATE
    include
    ${inih_SOURCE_DIR}
)

target_link_libraries(elden-ring-shared-damage PRIVATE
    minhook
    psapi
)

# Steam SDK — point STEAM_SDK_PATH at the root of the Steamworks SDK
# (the directory that contains public/ and redistributable_bin/).
# The game ships steam_api64.dll; we only need headers + the import lib.
# Example: cmake -B build -A x64 -DSTEAM_SDK_PATH=C:/steamworks_sdk_158
set(STEAM_SDK_PATH "C:/Steam/steamworks_sdk/sdk" CACHE PATH "Path to the Steamworks SDK root directory")
if(STEAM_SDK_PATH)
    target_include_directories(elden-ring-shared-damage PRIVATE
        "${STEAM_SDK_PATH}/public"
    )
    target_link_libraries(elden-ring-shared-damage PRIVATE
        "${STEAM_SDK_PATH}/redistributable_bin/win64/steam_api64.lib"
    )
else()
    message(WARNING
        "STEAM_SDK_PATH not set — Steam P2P networking will not compile. "
        "Pass -DSTEAM_SDK_PATH=<path> to cmake or set it in CMakeCache.txt.")
endif()

# Output the DLL directly into natives/ so me3 can pick it up immediately
set_target_properties(elden-ring-shared-damage PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY                "${CMAKE_SOURCE_DIR}/natives"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${CMAKE_SOURCE_DIR}/natives"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_SOURCE_DIR}/natives"
)

# Print the exact path of the built DLL after every build so there's no
# ambiguity about where the output landed.
add_custom_command(TARGET elden-ring-shared-damage POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Built DLL: $<TARGET_FILE:elden-ring-shared-damage>"
)