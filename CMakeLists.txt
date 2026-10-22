cmake_minimum_required(VERSION 3.20)
project(re2net_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /EHsc)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Engine-independent core: no REFramework, Lua or Windows types.
add_library(re2net_core STATIC
  core/src/types.cpp
  core/src/messages.cpp
  core/src/door_core.cpp)
target_include_directories(re2net_core PUBLIC core/include)

add_executable(re2net_core_tests tests/test_main.cpp)
target_link_libraries(re2net_core_tests PRIVATE re2net_core)
enable_testing()
add_test(NAME core_transactions COMMAND re2net_core_tests)

# Channel pump (plugin epoch logic) against a fake channel, plus a loopback self-test of
# the real LocalChannel worker inside the test process. No SDK, game or DLL.
if (WIN32)
  add_executable(re2net_adapter_tests tests/test_adapter.cpp adapter/reframework/pipe_transport.cpp)
  target_include_directories(re2net_adapter_tests PRIVATE adapter/reframework tests)
  target_link_libraries(re2net_adapter_tests PRIVATE re2net_core)
  add_test(NAME adapter_channel COMMAND re2net_adapter_tests)
endif()

# Replaceable REFramework plugin adapter. Built only when the reviewed, pinned SDK
# headers are supplied (RE2NET_REFRAMEWORK_SDK = folder containing reframework/API.hpp).
set(RE2NET_REFRAMEWORK_SDK "${CMAKE_CURRENT_SOURCE_DIR}/third_party/reframework/include" CACHE PATH "Pinned REFramework include directory (c4b1314, plugin API 1.15.0)")
if (RE2NET_REFRAMEWORK_SDK)
  add_library(re2net_door_plugin SHARED
    adapter/reframework/plugin_main.cpp
    adapter/reframework/re_engine_bridge.cpp
    adapter/reframework/pipe_transport.cpp)
  target_include_directories(re2net_door_plugin PRIVATE ${RE2NET_REFRAMEWORK_SDK} adapter/reframework)
  target_link_libraries(re2net_door_plugin PRIVATE re2net_core)
  target_compile_definitions(re2net_door_plugin PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

  # The actual bridge implementation against a fake C API (no SDK runtime, no engine).
  add_executable(re2net_adapter_probe tests/adapter_probe.cpp)
  target_include_directories(re2net_adapter_probe PRIVATE ${RE2NET_REFRAMEWORK_SDK} adapter/reframework)
  target_link_libraries(re2net_adapter_probe PRIVATE re2net_core)
  add_test(NAME adapter_probe COMMAND re2net_adapter_probe)
endif()
