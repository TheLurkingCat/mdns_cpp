cmake_minimum_required(VERSION 3.11)
project(
  mdns_cpp
  VERSION 0.1.0
  LANGUAGES CXX)

option(MDNS_CPP_BUILD_EXAMPLE "Build example executables" ON)

# Set the output of the libraries and executables.
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()

# ##############################################################################
# library
# ##############################################################################

add_library(${PROJECT_NAME})
target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
                         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_sources(
  ${PROJECT_NAME}
  PRIVATE include/mdns_cpp/defs.hpp
          src/mdns.h
          src/mdns.cpp
          include/mdns_cpp/mdns.hpp
          src/utils.cpp
          include/mdns_cpp/utils.hpp)

if(MSVC)
  target_compile_definitions(${PROJECT_NAME} PRIVATE "_CRT_SECURE_NO_WARNINGS")
  target_compile_options(${PROJECT_NAME} PRIVATE /W4)
else()
  target_compile_options(
    ${PROJECT_NAME}
    PRIVATE -Wall -Wextra -pedantic
            # mdns.h uses static functions in the header file
            -Wno-unused-function)
endif()

if(WIN32)
  target_link_libraries(${PROJECT_NAME} INTERFACE iphlpapi ws2_32)
endif()
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

# ##############################################################################
# example
# ##############################################################################

if(MDNS_CPP_BUILD_EXAMPLE)
  add_executable(${PROJECT_NAME}_discovery_example
                 ${CMAKE_CURRENT_LIST_DIR}/example/discovery.cpp)
  target_link_libraries(${PROJECT_NAME}_discovery_example ${PROJECT_NAME})
endif()
