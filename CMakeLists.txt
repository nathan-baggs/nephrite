cmake_minimum_required(VERSION 3.22)

project(
	nephrite
	VERSION "0.0.1"
	DESCRIPTION "nightfire hacking"
	LANGUAGES C CXX
)

include(FetchContent)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(FETCHCONTENT_QUIET FALSE)

add_executable(launch 
	src/launch.cpp
)

target_compile_features(launch PUBLIC cxx_std_23)
target_compile_options(launch PUBLIC /W3 /WX)

add_library(payload SHARED
	src/payload.cpp
)

target_compile_features(payload PUBLIC cxx_std_23)
target_compile_options(payload PUBLIC /W3 /WX)
