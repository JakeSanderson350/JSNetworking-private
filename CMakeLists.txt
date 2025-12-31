# set the minimum cmake version to generate projects.
cmake_minimum_required(VERSION 3.20.6)

project(
        gg-network
        LANGUAGES CXX
        VERSION 0.0.1 # todo: get this version from git tag
)

# ---- Add dependencies via CPM ----
# see https://github.com/TheLartians/CPM.cmake for more info
include(cmake/get_cpm.cmake)

# Set C++23 globally
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# include external libs
message("Git clonning doctest...")
CPMAddPackage("gh:doctest/doctest@2.4.12")

# include formating
message("Git clonning Format...")
CPMAddPackage("gh:TheLartians/Format.cmake@1.8.3")

# include boost
message("Downloading Boost... Do not stop the process, it may take a while...")
CPMAddPackage(
  NAME Boost
  VERSION 1.89.0
  URL https://github.com/boostorg/boost/releases/download/boost-1.89.0/boost-1.89.0-cmake.tar.xz
  URL_HASH SHA256=67acec02d0d118b5de9eb441f5fb707b3a1cdd884be00ca24b9a73c995511f74
  OPTIONS "BOOST_ENABLE_CMAKE ON" "BOOST_SKIP_INSTALL_RULES ON" # Set `OFF` for installation
          "BUILD_SHARED_LIBS OFF" "BOOST_INCLUDE_LIBRARIES container\\\;asio" # Note the escapes!
)

# include PcapPlusPlus
message("Downloading PcapPlusPlus... Do not stop the process, it may take a while...")
CPMAddPackage(
  NAME PcapPlusPlus
  VERSION 25.05
  URL https://github.com/seladb/PcapPlusPlus/archive/refs/tags/v25.05.tar.gz
  OPTIONS "PCAPPP_BUILD_EXAMPLES OFF" "PCAPPP_BUILD_TESTS OFF"
)

# Enable testing
enable_testing()

add_subdirectory(lib)
add_subdirectory(projects)