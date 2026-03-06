cmake_minimum_required(VERSION 3.21)
project(elden-ring-shared-damage CXX)

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

add_library(elden-ring-shared-damage SHARED
    src/dllmain.cpp
    src/hooks.cpp
    src/damage.cpp
)

target_include_directories(elden-ring-shared-damage PRIVATE
    include
)

target_link_libraries(elden-ring-shared-damage PRIVATE
    minhook
)

# Output the DLL directly into natives/ so me3 can pick it up immediately
set_target_properties(elden-ring-shared-damage PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY                "${CMAKE_SOURCE_DIR}/natives"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${CMAKE_SOURCE_DIR}/natives"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${CMAKE_SOURCE_DIR}/natives"
)
