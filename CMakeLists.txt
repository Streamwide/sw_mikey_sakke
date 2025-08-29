cmake_minimum_required(VERSION 3.12)
project(sw_mikey_sakke LANGUAGES    CXX
                       DESCRIPTION  "Implementation of TS33.180")

set(default_build_type "Debug")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    include(CTest)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDANT_CODE ON)

message(STATUS "C++ standard        : ${CMAKE_CXX_STANDARD}")
message(STATUS "C++ compiler        : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Generator           : ${CMAKE_GENERATOR}")

set (DIRLIBMUTIL           ./libmutil)
set (DIRLIBMCRYPTO         ./libmcrypto)
set (DIRLIBMIKEY           ./libmikey)
set (DIRLIBMIKEYSAKKE      ./libmikey-sakke)
set (DIRLIBKMSAGENT        ./kms-agent)

option(USE_SPDLOG       "Build with spdlog" OFF)
option(SECURED_REQUESTS "Adds a signed XML secure request element to the HTTP requests. (Not supported yet)" OFF)
option(OPENSSL_ONLY     "Use only Openssl for arithmetic. Will build without GMP" OFF)
option(BUILD_PHPLIB     "Build the library with PHP bindings" OFF)
option(ENGINE_BUILD     "Build the library for the engine" OFF)

if (USE_SPDLOG)
    message(STATUS "Building with spdlog")
else()
    message(STATUS "Building without spdlog")
endif()
if(OPENSSL_ONLY)
    message(STATUS "Building only with openssl")
else()
    message(STATUS "Building with GMP")
endif()

if(BUILD_SHARED_LIBS)
    set(OPENSSL_USE_STATIC_LIBS OFF)
else()
    set(OPENSSL_USE_STATIC_LIBS ON)
endif()

if(NOT TARGET LibXml2::LibXml2)
    find_package(LibXml2 REQUIRED)
endif()
message(STATUS "LibXml2 include dir: ${LIBXML2_INCLUDE_DIR}")
message(STATUS "LibXml2 libraries: ${LIBXML2_LIBRARIES}")

if(OPENSSL_ROOT_DIR OR NOT TARGET OpenSSL::Crypto OR NOT TARGET OpenSSL::SSL)
    find_package(OpenSSL)
endif()

if(TARGET OpenSSL::SSL OR TARGET OpenSSL::Crypto)
    message(STATUS "Building with OpenSSL version ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
else()
    message(STATUS "Can't find OpenSSL lib" ${OPENSSL_VERSION})
endif()

if(USE_SPDLOG)
    message(STATUS "spdlog include dir: ${SPDLOG_INCLUDE_DIR}")
    message(STATUS "spdlog libraries: ${SPDLOG_LIBRARIES}")
endif()

if(NOT TARGET CURL::libcurl)
    if(ENGINE_BUILD)
        find_package(CURL)
    else()
        message(STATUS "curl will be compiled from third_party")
    endif()
else()
    message(STATUS "curl include dir: ${CURL_INCLUDE_DIR}")
    message(STATUS "curl libraries: ${CURL_LIBRARIES}")
endif()

if(SECURED_REQUESTS)
    if(NOT TARGET xmlsec1-openssl OR NOT TARGET xmlsec1)
        message(STATUS "XMLSec1 will be compiled from third_party")
    else()
        message(STATUS "XMLSec1 include dir: ${XMLSEC1_INCLUDE_DIR}")
        message(STATUS "XMLSec1 libraries: ${XMLSEC1_LIBRARIES}")
    endif()
endif()

include(cmake_tools/sw_mikey_sakke_standalone.cmake)

file(GLOB libmcrypto_source_files
    CONFIGURE_DEPENDS
    ${DIRLIBMCRYPTO}/source/aes.cc
    ${DIRLIBMCRYPTO}/source/base64.cc
    ${DIRLIBMCRYPTO}/source/cert.cc
    ${DIRLIBMCRYPTO}/source/rijndael-alg-fst.cc
    ${DIRLIBMCRYPTO}/source/rand.cc
)

if (${OPENSSL_VERSION} VERSION_GREATER_EQUAL "3.0.0")
    message(STATUS "Using sources for OpenSSL3")
    file(GLOB libmcrypto_openssl_source_files CONFIGURE_DEPENDS ${DIRLIBMCRYPTO}/source/openssl3/*.cc)
    file(GLOB mscrypto_openssl_source_files CONFIGURE_DEPENDS ${DIRLIBMIKEYSAKKE}/src/mscrypto/hash/openssl3/*.cc)
elseif (${OPENSSL_VERSION} VERSION_GREATER_EQUAL "1.1.1")
    message(STATUS "Using sources for OpenSSL1")
    file(GLOB libmcrypto_openssl_source_files CONFIGURE_DEPENDS ${DIRLIBMCRYPTO}/source/openssl/*.cc)
    file(GLOB mscrypto_openssl_source_files CONFIGURE_DEPENDS ${DIRLIBMIKEYSAKKE}/src/mscrypto/hash/openssl/*.cc)
endif ()

file(GLOB libmikey_source_files
    CONFIGURE_DEPENDS
    ${DIRLIBMIKEY}/mikey/*.cc
    ${DIRLIBMIKEY}/keyagreement/*.cc
)

file(GLOB libmutil_source_files
    CONFIGURE_DEPENDS
    ${DIRLIBMUTIL}/source/*.cc
)

file(GLOB libkmsagent_source_files
    CONFIGURE_DEPENDS
    ${DIRLIBKMSAGENT}/src/KMClient.cc
    ${DIRLIBKMSAGENT}/src/KMSResponseParser.cc
)

if(OPENSSL_ONLY)
    file(GLOB libswmikeysakke_source_files
        CONFIGURE_DEPENDS
        ${DIRLIBMIKEYSAKKE}/src/*.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/eccsi.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/parameter-set-ossl.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/sakke-ossl.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/ecc/curve-openssl.cc
        ${DIRLIBMIKEYSAKKE}/src/util/bigint-ssl.cc
        ${DIRLIBMIKEYSAKKE}/src/util/time-measure.cc
        ${DIRLIBMIKEYSAKKE}/src/util/octet-string.cc
    )
else()
    file(GLOB libswmikeysakke_source_files
        CONFIGURE_DEPENDS
        ${DIRLIBMIKEYSAKKE}/src/*.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/eccsi.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/parameter-set.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/sakke.cc
        ${DIRLIBMIKEYSAKKE}/src/mscrypto/ecc/*.cc
        ${DIRLIBMIKEYSAKKE}/src/util/bigint.cc
        ${DIRLIBMIKEYSAKKE}/src/util/bigint-ssl.cc
        ${DIRLIBMIKEYSAKKE}/src/util/time-measure.cc
        ${DIRLIBMIKEYSAKKE}/src/util/octet-string.cc
    )
endif()

add_library(${PROJECT_NAME}
    ${libmcrypto_source_files}
    ${libmcrypto_openssl_source_files}
    ${libmikey_source_files}
    ${libmutil_source_files}
    ${libkmsagent_source_files}
    ${libswmikeysakke_source_files}
    ${mscrypto_openssl_source_files}
)

if(NOT SECURED_REQUESTS)
    target_compile_definitions(
        sw_mikey_sakke
        PRIVATE
        NO_XMLSEC=1
    )
endif()

if(OPENSSL_ONLY)
    target_compile_definitions(
        sw_mikey_sakke
        PRIVATE
        OPENSSL_ONLY
    )
endif()

target_include_directories(
    sw_mikey_sakke
    PUBLIC
    ${DIRLIBMIKEYSAKKE}/include
)

target_include_directories(
    sw_mikey_sakke
    PUBLIC
    ${DIRLIBMCRYPTO}/include
    ${DIRLIBMIKEY}/include
    ${DIRLIBMUTIL}/include
    ${DIRLIBKMSAGENT}/include
    ${LIBXML2_INCLUDE_DIR} #FindXml2 does not add the includes to the xml2 target
    PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

target_compile_options(sw_mikey_sakke
    PRIVATE
    -Wall -Werror -Wextra
    -Wno-shorten-64-to-32
)

set_target_properties(
    sw_mikey_sakke
    PROPERTIES
    CXX_STANDARD 17
)

target_link_libraries(sw_mikey_sakke PRIVATE stdc++)
if(NOT OPENSSL_ONLY)
    target_link_libraries(sw_mikey_sakke PRIVATE gmp gmpxx)
endif()

if(SECURED_REQUESTS)
    target_link_libraries(sw_mikey_sakke PRIVATE xmlsec1-openssl)
    target_link_libraries(sw_mikey_sakke PRIVATE xmlsec1)
endif()

if(USE_SPDLOG)
    target_link_libraries(sw_mikey_sakke PRIVATE spdlog::spdlog)
endif()
target_link_libraries(sw_mikey_sakke PRIVATE CURL::libcurl)
target_link_libraries(sw_mikey_sakke PRIVATE LibXml2::LibXml2)
target_link_libraries(sw_mikey_sakke PRIVATE OpenSSL::SSL OpenSSL::Crypto)

include(cmake_tools/versions.cmake)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_custom_target(cppcheck
                    COMMAND cppcheck
                    --enable=all
                    --suppress=missingInclude
                    --suppress=noExplicitConstructor
                    --suppress=unusedFunction
                    --suppress=toomanyconfigs
                    --std=c++17
                    -UWIN32
                    -UTEST_BIGINT
                    -UTEST_BIGINT_SSL
                    -UTEST_SAKKE
                    -U__BASE_FILE__
                    -U_MSC_VER
                    -U__SDCC_VERSION_MAJOR
                    -USDCC
                    -I ${PROJECT_SOURCE_DIR}/libmikey/include/
                    -I ${PROJECT_SOURCE_DIR}/libmutil/include/
                    -I ${PROJECT_SOURCE_DIR}/kms-agent/include/
                    -I ${PROJECT_SOURCE_DIR}/libmcrypto/include/
                    -I ${PROJECT_SOURCE_DIR}/libmikey-sakke/mscrypto/include/
                    -I ${PROJECT_SOURCE_DIR}/libmikey-sakke/mskms/client/include/
                    -I ${PROJECT_SOURCE_DIR}/libmikey-sakke/util/include/
                    -I ${PROJECT_SOURCE_DIR}/libmikey-sakke/mikeysakke4c/include/
                    ${PROJECT_SOURCE_DIR}
                    -i ${PROJECT_SOURCE_DIR}/lib/
                    -i ${PROJECT_SOURCE_DIR}/unit_tests/
                    2> cppcheck.txt
    )
    add_subdirectory(unit_tests)
endif()

if(BUILD_PHPLIB)
    add_subdirectory(php_)
endif()
