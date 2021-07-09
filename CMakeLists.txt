cmake_minimum_required(VERSION "3.15")
project("hookftw_example")

# include header files of hookFTW 
include_directories(hookftw/library/src)

# gather source files of this example
file(GLOB_RECURSE EXAMPLE_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)

# build hookFTW
add_subdirectory(hookftw)

# add hookftw_example.exe
add_library (hookftw_example SHARED ${EXAMPLE_SOURCES})

# link hookFTW
target_link_libraries(hookftw_example hookftw)

# link dbghelp (required to resolve debug symbols)
target_link_libraries(hookftw_example dbghelp)