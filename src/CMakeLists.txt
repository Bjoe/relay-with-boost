
add_executable(btur)

target_sources(btur
 PRIVATE
    main.cpp
    TcpRelayServer.cpp
    TcpRelayServer.hpp
    UdpRelayServer.cpp
    UdpRelayServer.hpp
)
target_link_libraries(
  btur
  PUBLIC
  project_options
  project_warnings

  Boost::headers
  Boost::program_options
  Boost::log

#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(btur PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
