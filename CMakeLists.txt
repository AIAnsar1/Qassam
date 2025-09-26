cmake_minimum_required(VERSION 4.0)
project(qassam)

set(CMAKE_CXX_STANDARD 20)

add_executable(qassam main.cpp
        kernel/qassam_engine.hh
        kernel/qassam_support.hh
        support/qassam_support.cc)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(Boost_ROOT "/usr/local")
find_package(Boost REQUIRED COMPONENTS filesystem system)
find_package(Boost REQUIRED COMPONENTS filesystem system regex thread chrono ...)
target_include_directories(qassam PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(qassam PRIVATE ${Boost_LIBRARIES})
include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
