cmake_minimum_required(VERSION "3.15")
project("hookftw_example")

# include header files of hookFTW 
include_directories(hookftw/library/src)

# gather source files of this example
file(GLOB_RECURSE EXAMPLE_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)

# Add hookftw_example.dll
add_library (hookftw_example SHARED ${EXAMPLE_SOURCES})

#include to also build hookFTW
#add_subdirectory(hookftw)