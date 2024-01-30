cmake_minimum_required(VERSION 3.12) # Minimum version required for C++20 support

# Project name and language
project(shadow-of-war-save-editor CXX)

# Set the C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Collect all source files from the ./src directory
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create a shared library (Windows DLL) target from the source files
add_library(shadow-of-war-save-editor SHARED ${SOURCES})

# Set the output directory for the library
set_target_properties(shadow-of-war-save-editor PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Enable position-independent code (PIC) for the library target
set_target_properties(shadow-of-war-save-editor PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Define a macro to specify that the library is being built as a DLL
target_compile_definitions(shadow-of-war-save-editor PRIVATE SHADOWOFWAR_EXPORTS)

# Specify include directories for the library target
target_include_directories(shadow-of-war-save-editor PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Specify the directory where the linker should search for libraries
link_directories("/lib")