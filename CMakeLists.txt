cmake_minimum_required(VERSION 3.20)

project(PcapConstrictorBPF C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(packet_policy src/core/packet_policy.c)
target_include_directories(packet_policy PUBLIC src/core)

add_executable(policy_tests tests/policy_tests/main.c)
target_link_libraries(policy_tests PRIVATE packet_policy)

enable_testing()
add_test(NAME policy_tests COMMAND policy_tests)
