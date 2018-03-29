cmake_minimum_required(VERSION 3.10)
project(c_libp2p_crypto C)

set(CMAKE_C_STANDARD 99)

FIND_PACKAGE(Protobuf REQUIRED)
INCLUDE_DIRECTORIES(${PROTOBUF_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})

# set(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
# set(CMAKE_CXX_STANDARD 11)
# set(protobuf_BUILD_TESTS OFF)
# add_subdirectory(protobuf/cmake)
# add_subdirectory(protobuf-c/build-cmake)
include(protobuf-c.cmake)

set(LIBP2P_CRYPTO_SRC
        crypto/aes/aes.c
        crypto/aes/aes.h
        crypto/util.h
        crypto/util.c
        crypto/keys/common.h
        crypto/keys/keys.c
        crypto/keys/keys.h
        crypto/keys/rsa.c
        crypto/keys/rsa.h
        )

set_source_files_properties(
        ${LIBP2P_CRYPTO_SRC}
        PROPERTIES
        COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
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

add_library(c_libp2p_crypto ${LIBP2P_CRYPTO_SRC_FULL})
