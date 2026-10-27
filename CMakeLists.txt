cmake_minimum_required(VERSION 3.21)
project(atlas_login_agent VERSION 0.1.0 LANGUAGES CXX)

option(ATLAS_BUILD_TESTS "Build the unit tests" ON)
if(WIN32)
  option(ATLAS_BUILD_PROVIDER "Build the Windows credential provider, enrol and sync tools" ON)
else()
  option(ATLAS_BUILD_PROVIDER "Build the Windows credential provider (Windows only)" OFF)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

find_package(OpenSSL 3 REQUIRED)

include(FetchContent)
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
  FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3 GIT_SHALLOW TRUE)
  set(JSON_BuildTests OFF CACHE INTERNAL "")
  set(JSON_Install OFF CACHE INTERNAL "")
  FetchContent_MakeAvailable(nlohmann_json)
endif()

add_library(atlas_core STATIC
  src/core/base.cpp src/core/crypto.cpp src/core/softkey.cpp src/core/offline.cpp
  src/core/config.cpp src/core/client.cpp src/core/gate.cpp)
target_include_directories(atlas_core PUBLIC include)
target_link_libraries(atlas_core PUBLIC nlohmann_json::nlohmann_json PRIVATE OpenSSL::Crypto)
if(MSVC)
  target_compile_options(atlas_core PRIVATE /W4 /utf-8)
else()
  target_compile_options(atlas_core PRIVATE -Wall -Wextra)
endif()

if(ATLAS_BUILD_TESTS)
  enable_testing()
  find_package(GTest QUIET)
  if(NOT GTest_FOUND)
    FetchContent_Declare(googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.15.2 GIT_SHALLOW TRUE)
    set(INSTALL_GTEST OFF CACHE INTERNAL "")
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()
  add_executable(atlas_core_tests tests/core_tests.cpp tests/flow_tests.cpp)
  target_link_libraries(atlas_core_tests PRIVATE atlas_core GTest::gtest_main OpenSSL::Crypto)
  target_compile_definitions(atlas_core_tests PRIVATE
    ATLAS_VECTORS_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdata/protocol-vectors.json")
  include(GoogleTest)
  gtest_discover_tests(atlas_core_tests DISCOVERY_MODE PRE_TEST)
endif()

if(ATLAS_BUILD_PROVIDER)
  if(NOT WIN32)
    message(FATAL_ERROR "ATLAS_BUILD_PROVIDER needs Windows")
  endif()
  add_subdirectory(src/provider)
endif()
