
add_executable(btur)

target_sources(btur
 PRIVATE
    main.cpp
    options.hpp
    TcpRelayServer.cpp
    TcpRelayServer.hpp
    UdpRelayServer.cpp
    UdpRelayServer.hpp

    sockmap/tbpf.h
    sockmap/tbpf.c
    sockmap/sockmap-ebpf.c

    iosubmit.h
    sockmap.h
)

target_link_libraries(
  btur
  PUBLIC
  project_options
  project_warnings


  libbpf::libbpf
  Boost::headers
  Boost::program_options
  Boost::log

#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(btur PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")


install(TARGETS btur
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
