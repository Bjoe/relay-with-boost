

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

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    target_sources(btur
        PRIVATE
        aarch64/vmlinux.h
    )
    target_include_directories(btur
        PUBLIC
        "${CMAKE_SOURCE_DIR}/src/aarch64/uapi"
        "${CMAKE_SOURCE_DIR}/src/aarch64"
    )
    set(ARCH "arm64")
    set(BPFOBJECT_VMLINUX_H "${CMAKE_SOURCE_DIR}/src/aarch64/vmlinux.h")
else()
    target_sources(btur
        PRIVATE
        x86/vmlinux.h
    )
    target_include_directories(btur
        PUBLIC
        "${CMAKE_SOURCE_DIR}/src/x86"
    )
    set(ARCH "x86")
    set(BPFOBJECT_VMLINUX_H "${CMAKE_SOURCE_DIR}/src/x86/vmlinux.h")
endif()

# Build object skeleton and depend skeleton on libbpf build
bpf_object(sockmap sockmap.bpf.c)

target_link_libraries(
  btur
  PUBLIC
  project_options
  project_warnings

  sockmap_skel

  #libbpf::libbpf
  PkgConfig::libbpf
  Boost::headers
  Boost::program_options
  Boost::log

#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(btur
    PUBLIC
    "${CMAKE_BINARY_DIR}/configured_files/include"
    "${CMAKE_BINARY_DIR}/src"
)


install(TARGETS btur
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
