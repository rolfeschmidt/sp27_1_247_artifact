cmake_minimum_required(VERSION 3.16)
project(sm_framework LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(sm_framework INTERFACE)
target_include_directories(sm_framework INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(framework_tests tests/framework_tests.cpp)
target_link_libraries(framework_tests PRIVATE sm_framework)

add_executable(agg_unikem_experiment tools/agg_unikem_experiment.cpp)
target_link_libraries(agg_unikem_experiment PRIVATE sm_framework)

enable_testing()
add_test(NAME framework_tests COMMAND framework_tests)
