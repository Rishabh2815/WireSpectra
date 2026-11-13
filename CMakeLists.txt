cmake_minimum_required(VERSION 3.16)
project(WireSpectra VERSION 1.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

add_executable(packet_analyzer
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
target_include_directories(packet_analyzer PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(packet_analyzer PRIVATE OpenSSL::Crypto Threads::Threads PkgConfig::PCAP)
if(MSVC)
    target_compile_options(packet_analyzer PRIVATE /W4)
else()
    target_compile_options(packet_analyzer PRIVATE -Wall -Wextra -Wpedantic)
endif()
