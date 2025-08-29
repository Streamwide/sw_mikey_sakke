cmake_minimum_required(VERSION 3.25)
project(kms_agent)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(ExternalProject)
message("C++ standard : ${CMAKE_CXX_STANDARD}")

set (DIRSPDLOG              ../lib/spdlog)
set (DIRLIBMCRYPTO          ../libmcrypto)

ExternalProject_Add(spdlog
    URL ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/spdlog-v1.8.5.tar.gz
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${DIRSPDLOG}
    PREFIX build/
    CONFIGURE_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/${DIRSPDLOG} && mkdir build
    BUILD_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/${DIRSPDLOG}/build && cmake .. && make -j
    INSTALL_COMMAND ""
)

find_package(LibXml2 REQUIRED)
if (${LIBXML2_FOUND} EQUAL false)
    message("Could not find libxml2")
else()
    include_directories(
        ${LIBXML2_INCLUDE_DIR}
    )
endif()

include_directories(
    ./include
    /usr/include/xmlsec1/
    ../libmikey-sakke/util/include/
    ../libmcrypto/include/
    ${CMAKE_CURRENT_SOURCE_DIR}/${DIRSPDLOG}/include
)

set(source_files
    "./src/KMClient.cc"
    "./src/KMSResponseParser.cc"
)

set(main
    "./src/main.cc"
)

add_compile_options(-g -Wall -Werror -fPIC)
add_definitions(-DXMLSEC_CRYPTO_OPENSSL)

add_library(kms_agent STATIC ${source_files})
add_executable(test_app ${source_files} ${main})

add_dependencies(kms_agent spdlog)
add_dependencies(test_app spdlog)

target_link_libraries(kms_agent curl)
target_link_libraries(kms_agent xml2)
target_link_libraries(kms_agent xmlsec1)
target_link_libraries(kms_agent xmlsec1-openssl)
target_link_libraries(kms_agent ${CMAKE_CURRENT_SOURCE_DIR}/${DIRSPDLOG}/build/libspdlog.a)
target_link_libraries(kms_agent ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBMCRYPTO}/libmcrypto.a)

target_link_libraries(test_app curl)
target_link_libraries(test_app xml2)
target_link_libraries(test_app xmlsec1)
target_link_libraries(test_app xmlsec1-openssl)
target_link_libraries(test_app ${CMAKE_CURRENT_SOURCE_DIR}/${DIRSPDLOG}/build/libspdlog.a)
target_link_libraries(test_app ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBMCRYPTO}/libmcrypto.a)

include(${CMAKE_SOURCE_DIR}/cmake_tools/unit_tests.cmake)
