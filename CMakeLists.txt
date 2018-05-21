cmake_minimum_required(VERSION 3.10)

set(prog pcap_learning)

add_library(${prog} STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/${prog}.cpp)
target_link_libraries (${prog} pcap)
target_include_directories (${prog} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(prog pcap_demo)
add_executable( ${prog} ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp )
target_link_libraries (${prog} pcap_learning pthread)
target_include_directories (${prog} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
