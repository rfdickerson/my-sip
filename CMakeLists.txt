cmake_minimum_required(VERSION 3.20)
project(janus_cpp_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BUILD_PJSIP "Build vendored PJSIP with ExternalProject" OFF)

set(PJSIP_ROOT "" CACHE PATH "Path to PJSIP build/install prefix")

if(BUILD_PJSIP)
  include(ExternalProject)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/pjsip/configure")
    message(FATAL_ERROR "PJSIP source not found. Place PJSIP in third_party/pjsip or set PJSIP_ROOT.")
  endif()

  set(PJSIP_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/pjsip")
  set(PJSIP_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/pjsip-build")
  set(PJSIP_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/pjsip-install")

  ExternalProject_Add(pjsip
    SOURCE_DIR "${PJSIP_SRC_DIR}"
    BINARY_DIR "${PJSIP_BUILD_DIR}"
    CONFIGURE_COMMAND "${PJSIP_SRC_DIR}/configure" --enable-shared --prefix="${PJSIP_INSTALL_DIR}"
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 0
  )

  set(PJSIP_ROOT "${PJSIP_INSTALL_DIR}")
endif()

if(NOT PJSIP_ROOT)
  message(FATAL_ERROR "Set PJSIP_ROOT to the PJSIP install prefix (contains include/ and lib/).")
endif()

add_executable(sip_smoke
  src/main.cpp
)

target_include_directories(sip_smoke PRIVATE
  "${PJSIP_ROOT}/include"
)

set(PJSIP_LIB_DIR "${PJSIP_ROOT}/lib")

# Link explicitly to the PJSIP libs in the chosen prefix to avoid ABI mismatches.
target_link_libraries(sip_smoke PRIVATE
  "${PJSIP_LIB_DIR}/libpjsua2.so"
  "${PJSIP_LIB_DIR}/libpjsua.so"
  "${PJSIP_LIB_DIR}/libpjsip-ua.so"
  "${PJSIP_LIB_DIR}/libpjsip-simple.so"
  "${PJSIP_LIB_DIR}/libpjsip.so"
  "${PJSIP_LIB_DIR}/libpjmedia-codec.so"
  "${PJSIP_LIB_DIR}/libpjmedia-videodev.so"
  "${PJSIP_LIB_DIR}/libpjmedia-audiodev.so"
  "${PJSIP_LIB_DIR}/libpjmedia.so"
  "${PJSIP_LIB_DIR}/libpjnath.so"
  "${PJSIP_LIB_DIR}/libpjlib-util.so"
  "${PJSIP_LIB_DIR}/libpj.so"
)

# Ensure runtime loader prefers the same prefix.
set_target_properties(sip_smoke PROPERTIES
  BUILD_RPATH "${PJSIP_LIB_DIR}"
  INSTALL_RPATH "${PJSIP_LIB_DIR}"
)

# System libs commonly required by PJSIP (may vary by distro)
find_package(Threads REQUIRED)
target_link_libraries(sip_smoke PRIVATE Threads::Threads)
