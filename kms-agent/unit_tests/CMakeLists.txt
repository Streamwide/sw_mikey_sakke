##################################
# Download and install GoogleTest


include(ExternalProject)
ExternalProject_Add(gtest
    URL https://github.com/google/googletest/archive/refs/tags/release-1.10.0.zip
    PREFIX ""
    INSTALL_COMMAND ""
    CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
)
ExternalProject_Get_Property(gtest source_dir binary_dir)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB files "test_*.cc")
foreach(file ${files})
    get_filename_component(file_exe ${file} NAME_WE)
    message(STATUS "${file_exe}")

    ################
    add_executable(${file_exe} ${file})
    target_link_libraries(${file_exe} Threads::Threads)

    ######################################
    # Configure the test to use GoogleTest
    #
    # If used often, could be made a macro.
    add_dependencies(${file_exe} gtest)
    add_dependencies(${file_exe} kms_agent)
    include_directories(${source_dir}/googletest/include)

    target_link_libraries(${file_exe} ${CMAKE_CURRENT_BINARY_DIR}/gtest-prefix/src/gtest-build/lib/libgtest.a)
    target_link_libraries(${file_exe} ${CMAKE_CURRENT_BINARY_DIR}/gtest-prefix/src/gtest-build/lib/libgtest_main.a)
    target_link_libraries(${file_exe} ${CMAKE_CURRENT_BINARY_DIR}/../libkms_agent.a)
    target_link_libraries(${file_exe} ${CMAKE_CURRENT_BINARY_DIR}/../../libmcrypto/libmcrypto.a)
    target_link_libraries(${file_exe} curl)
    target_link_libraries(${file_exe} xml2)
    target_link_libraries(${file_exe} xmlsec1)
    target_link_libraries(${file_exe} xmlsec1-openssl)

    target_link_libraries(${file_exe} dl)
    target_link_libraries(${file_exe} unwind-x86_64 unwind)
    target_link_libraries(${file_exe} -fPIC)
    target_link_libraries(${file_exe} -lgcov --coverage)

    ##################################
    # Just make the test runnable with
    #   $ make test

    add_test(
        NAME ${file_exe}
        COMMAND ${file_exe} --gtest_output=xml:${file_exe}.xml)

endforeach()


