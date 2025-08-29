include(FetchContent)
include(ExternalProject)

set (DIRLIBOPENSSL         ./lib/openssl)
set (DIROPENSSL            ./lib/openssl)
set (DIRLIBSPDLOG          ./lib/spdlog)
set (DIRLIBCURL            ./lib/curl)
set (DIRLIBXMLSEC1         ./lib/xmlsec1)

if(NOT TARGET OpenSSL::Crypto OR NOT TARGET OpenSSL::SSL)
    file(GLOB ARCHIVE_OPENSSL "${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl-3.?.?.tar.gz")
    cmake_path(GET ARCHIVE_OPENSSL STEM STEM_OPENSSL)

    set(OSSL_FOUND FALSE CACHE BOOL "Whether OpenSSL has been found already")

    if (NOT OSSL_FOUND)
    message(STATUS "Building OpenSSL before everything else")
    # According to cmake doc https://cmake.org/cmake/help/latest/command/execute_process.html
    # "For sequential execution of multiple commands use multiple execute_process calls each with a single COMMAND argument."
    execute_process(
        COMMAND mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBOPENSSL}
        )
    execute_process(
        COMMAND tar -xzf ${ARCHIVE_OPENSSL} -C ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBOPENSSL} --strip-components=1
        # We use this instead of file(ARCHIVE_EXTRACT..) because it allows us to strip the extracted directory
    )
    execute_process(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBOPENSSL}
        COMMAND ./Configure threads no-comp
    )
    execute_process(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBOPENSSL}
        COMMAND make -j5
    )
    set(OSSL_FOUND TRUE CACHE BOOL "Whether OpenSSL has been found already" FORCE)
    endif()

    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBOPENSSL})
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)
endif()

if(USE_SPDLOG AND NOT TARGET spdlog::spdlog)
    message(STATUS "Caller did not supply spdlog path, building it ourself")
    set(SPDLOG_BUILD_EXAMPLE OFF CACHE INTERNAL "")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE INTERNAL "")

    FetchContent_Declare(
        spdlog
        EXCLUDE_FROM_ALL
        URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/spdlog-1.10.0.tar.gz
    )
    FetchContent_MakeAvailable(spdlog)
endif()

if(NOT TARGET CURL::libcurl)
    message(STATUS "Caller did not supply curl path, building it ourself")
    set(BUILD_CURL_EXE OFF CACHE INTERNAL "")
    set(CURL_DISABLE_TESTS ON CACHE INTERNAL "")
    set(USE_OPENSSL ON CACHE INTERNAL "")
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_CRYPTO_LIBRARY} CACHE INTERNAL "")
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_SSL_LIBRARY} CACHE INTERNAL "")
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR} CACHE INTERNAL "")
    set(USE_LIBIDN2 OFF CACHE INTERNAL "")
    set(USE_ZLIB OFF CACHE INTERNAL "")
    set(CMAKE_USE_LIBSSH2 OFF CACHE INTERNAL "")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE INTERNAL "")

    FetchContent_Declare(
        libcurl
        EXCLUDE_FROM_ALL
        URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/curl-7.85.0.tar.gz
    )
    FetchContent_MakeAvailable(libcurl)
endif()

if(SECURED_REQUESTS)
if(NOT TARGET xmlsec1-openssl OR NOT TARGET xmlsec1)
    message(STATUS "Caller did not supply xmlsec1 path, building it ourself")
    set(XMLSEC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${DIRLIBXMLSEC1})

    FetchContent_Declare(
        xmlsec1
        EXCLUDE_FROM_ALL
        URL             ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xmlsec1-1.2.34.tar.gz
        SOURCE_DIR      ${XMLSEC_SOURCE_DIR}
        SOURCE_SUBDIR   ../build/xmlsec1
    )
    FetchContent_MakeAvailable(xmlsec1)

endif()
endif()

if(NOT OPENSSL_ONLY AND (NOT TARGET gmp OR NOT TARGET gmpxx))
    set (DIRLIBGMP ./lib/gmp)

    ExternalProject_Add(libgmp
        URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/gmp-6.2.1.tar.xz
        SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP}
        CONFIGURE_COMMAND cd <SOURCE_DIR> &&
            ./configure --disable-shared --enable-cxx --with-pic
        BUILD_COMMAND make -C <SOURCE_DIR>
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP}/.libs/libgmp.a ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP}/.libs/libgmpxx.a
    )

    add_library(gmp STATIC IMPORTED)
    set_property(TARGET gmp PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP}/.libs/libgmp.a)
    set_property(TARGET gmp PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP})
    add_dependencies(gmp libgmp)

    add_library(gmpxx STATIC IMPORTED)
    set_property(TARGET gmpxx PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP}/.libs/libgmpxx.a)
    set_property(TARGET gmpxx PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/${DIRLIBGMP})
    add_dependencies(gmpxx libgmp)
endif()