

add_executable(btur)

target_sources(btur
 PRIVATE
    main.cpp
    options.hpp
    TcpRelayServer.cpp
    TcpRelayServer.hpp
    UdpRelayServer.cpp
    UdpRelayServer.hpp

    iosubmit.h
    sockmap.h
)

# Build object skeleton and depend skeleton on libbpf build
bpf_object(sockmap sockmap.bpf.c)

target_link_libraries(
  btur
  PUBLIC
  project_options
  project_warnings

  sockmap_skel

  ${LIBBPF_LIBRARIES}
  #libbpf::libbpf
  Boost::headers
  Boost::program_options
  Boost::log

#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(btur
    PUBLIC
    "${CMAKE_BINARY_DIR}/configured_files/include"
    "${CMAKE_BINARY_DIR}/src"
    "${LIBBPF_INCLUDE_DIRS}"
)


install(TARGETS btur
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
