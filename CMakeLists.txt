cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set(CMAKE_VERBOSE_MAKEFILE_ON)

# The following must be set BEFORE doing project() or enable_language().
if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type defined; defaulting to 'Debug'")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
    "The type of build. Possible values are: Debug, Release, RelWithDebInfo and MinSizeRel.")
endif ()

set(PACKAGE "stubby")
set(PACKAGE_NAME "Stubby")
set(PACKAGE_VERSION "0.2.6")
set(PACKAGE_BUGREPORT "team@getdnsapi.net")

set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}-${PACKAGE_VERSION}")

set(STUBBY_PACKAGE "${PACKAGE}")
set(STUBBY_PACKAGE_STRING "${PACKAGE_STRING}")

project (stubby VERSION ${PACKAGE_VERSION} LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(CheckIncludeFile)
include(GNUInstallDirs)

# Directories
if (DEFINED CMAKE_INSTALL_FULL_RUNSTATEDIR)
  set(RUNSTATEDIR "${CMAKE_INSTALL_FULL_RUNSTATEDIR}")
else ()
  set(RUNSTATEDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run")
endif ()
install(DIRECTORY
  DESTINATION ${RUNSTATEDIR}
  DIRECTORY_PERMISSIONS
  OWNER_READ OWNER_WRITE OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE
  )
set(STUBBYCONFDIR "${RUNSTATEDIR}/stubby")

# Are we being built from getdns?
if (TARGET getdns)
  set(getdns_lib "getdns")
else ()
  find_package(Getdns "1.5.0" REQUIRED)
  set(getdns_lib "Getdns::Getdns")
endif ()
find_package(Libyaml REQUIRED)

if (WIN32)
  set(STUBBY_ON_WINDOWS 1)
endif ()

check_include_file(os/log.h HAVE_OS_LOG_H)

# Does the compiler accept the "format" attribute?
try_compile(HAVE_ATTR_FORMAT
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests/test_format_attr.c
  )
# Does the compiler accept the "unused" attribute?
try_compile(HAVE_ATTR_UNUSED
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests/test_unused_attr.c
  )

configure_file(cmake/include/cmakeconfig.h.in config.h)
set(ETCDIR "${STUBBYCONFDIR}")
configure_file(doc/stubby.1.in stubby.1 @ONLY)

add_executable(stubby
  src/stubby.c
  src/yaml/convert_yaml_to_json.c
  src/sldns/sbuffer.c
  )
target_include_directories(stubby PRIVATE src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(stubby PRIVATE ${getdns_lib} Libyaml::Libyaml)
set_property(TARGET stubby PROPERTY C_STANDARD 11)

install(TARGETS stubby)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/stubby.1 DESTINATION share/man/man1)
install(FILES AUTHORS COPYING ChangeLog INSTALL NEWS README.md DESTINATION share/doc/stubby)

if (WIN32)
  # Attempt to ensure the file gets CRLF line endings.
  file(STRINGS src/stubby.yml conf)
  file(WRITE stubby.yml ${conf})
  install(FILES stubby.yml DESTINATION ${STUBBYCONFDIR}/stubby.yml)
else ()
  install(FILES src/stubby.yml.example DESTINATION ${STUBBYCONFDIR}/stubby.yml)
endif ()

if (APPLE)
  find_library(security Security REQUIRED)
  add_executable(stubby-ui-helper macos/stubby-ui-helper.c)
  target_include_directories(stubby-ui-helper PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(stubby-ui-helper ${security})

  install(FILES macos/stubby-setdns-macos.sh DESTINATION sbin)
endif ()
