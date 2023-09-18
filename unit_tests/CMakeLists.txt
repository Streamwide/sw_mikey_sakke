include(FetchContent)
include(GoogleTest)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.13.0
)
FetchContent_GetProperties(googletest)

if(NOT googletest_POPULATED)
    FetchContent_Populate(googletest)
    add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR})
endif()


file(GLOB files
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_LIST_DIR}/test_*.cc
    ${CMAKE_CURRENT_LIST_DIR}/*gen.cc
)

file(GLOB test_data
    ../${DIRLIBMIKEYSAKKE}/src/test_data.cc
)

message(STATUS "Building the following unit tests:")

foreach(file ${files})
    get_filename_component(file_exe ${file} NAME_WE)
    message(STATUS "${file_exe}")

    add_executable(${file_exe} ${file} ${test_data})
    set_target_properties(
        ${file_exe}
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    )

    target_include_directories(
        ${file_exe}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/${DIRLIBMIKEY}/include
        ${CMAKE_SOURCE_DIR}/${DIRLIBMUTIL}/include
        ${CMAKE_SOURCE_DIR}/${DIRLIBMCRYPTO}/include
        ${CMAKE_SOURCE_DIR}/${DIRLIBKMSAGENT}/include
        ${LIBXML2_INCLUDE_DIR}
    )

    target_compile_options(${file_exe} PRIVATE -g -fstack-protector -fPIC)

    target_link_libraries(${file_exe} PRIVATE GTest::gtest_main)
    target_link_libraries(${file_exe} PRIVATE sw_mikey_sakke)

    gtest_discover_tests(
        ${file_exe}
        EXTRA_ARGS --gtest_output=xml:${file_exe}.xml
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unit_tests
    )

endforeach()