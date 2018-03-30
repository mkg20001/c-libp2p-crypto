cmake_minimum_required(VERSION 3.10)
project(c_libp2p_crypto C)

set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})

if (NOT_INCLUDE_PROTOBUF_C)
else()
    include(protobuf-c.cmake)
endif()

set(LIBP2P_CRYPTO_SRC
        crypto/aes/aes.c
        crypto/aes/aes.h
        crypto/util.c
        crypto/util.h
        crypto/keys/common.h
        crypto/keys/keys.c
        crypto/keys/keys.h
        crypto/keys/rsa.c
        crypto/keys/rsa.h
        )

set_source_files_properties(
        ${LIBP2P_CRYPTO_SRC}
        PROPERTIES
        COMPILE_FLAGS "-Werror"
)

set(LIBP2P_CRYPTO_SRC_FULL
        ${LIBP2P_CRYPTO_SRC}
        protos/key.pb-c.c
        protos/key.pb-c.h
        protobuf-c/protobuf-c/protobuf-c.c
        protobuf-c/protobuf-c/protobuf-c.h
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

macro(compile_proto_file filename)
    get_filename_component(basename ${filename} NAME_WE)
    add_custom_command(
            OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.c ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.h
            DEPENDS ${PROTOBUF_PROTOC_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.proto
            COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.proto
            --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/protos
            --plugin=$<TARGET_FILE:protoc-gen-c>
            --c_out=${CMAKE_CURRENT_SOURCE_DIR}/protos
    )
endmacro(compile_proto_file)

file(GLOB PROTOS "${CMAKE_CURRENT_SOURCE_DIR}/protos/*.proto")
foreach(proto_file ${PROTOS})
    compile_proto_file(${proto_file})
endforeach(proto_file)

add_library(c_libp2p_crypto SHARED ${LIBP2P_CRYPTO_SRC_FULL})
target_link_libraries(c_libp2p_crypto ${OPENSSL_LIBRARIES})

include(gtest.cmake)

set(TEST_FILES
        test/crypto/aes.cpp)

add_executable(crypto_test test/main.cpp ${TEST_FILES})

target_link_libraries(crypto_test
        c_libp2p_crypto
        libgtest
        libgmock)

install(TARGETS crypto_test DESTINATION bin)
