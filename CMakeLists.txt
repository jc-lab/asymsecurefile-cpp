cmake_minimum_required(VERSION 3.4)
project(asymsecurefile)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(jcp)

include_directories(${CMAKE_SOURCE_DIR}/jcp/include)
include_directories(${CMAKE_SOURCE_DIR})
add_library(asymsecurefile asymsecurefile/asym_algorithm.cpp asymsecurefile/asym_algorithm.hpp asymsecurefile/chunk.cpp asymsecurefile/chunk.hpp asymsecurefile/data_algorithm.cpp asymsecurefile/data_algorithm.hpp asymsecurefile/frame.cpp asymsecurefile/frame.hpp asymsecurefile/input_stream.cpp asymsecurefile/input_stream.hpp asymsecurefile/internal/byte_buffer.cpp asymsecurefile/internal/byte_buffer.hpp asymsecurefile/internal/input_stream_delegate.hpp asymsecurefile/internal/jasf3/algorithm_info.hpp asymsecurefile/internal/jasf3/asym_algorithm_chunk.hpp asymsecurefile/internal/jasf3/data_algorithm_chunk.hpp asymsecurefile/internal/jasf3/data_iv_chunk.hpp asymsecurefile/internal/jasf3/default_header_chunk.hpp asymsecurefile/internal/jasf3/encrypted_seed_key_chunk.hpp asymsecurefile/internal/jasf3/footer_chunk.hpp asymsecurefile/internal/jasf3/jasf3_chunk_resolver.cpp asymsecurefile/internal/jasf3/jasf3_chunk_resolver.hpp asymsecurefile/internal/jasf3/jasf3_chunk_type.hpp asymsecurefile/internal/jasf3/jasf3_input_stream_delegate.cpp asymsecurefile/internal/jasf3/jasf3_input_stream_delegate.hpp asymsecurefile/internal/jasf3/jasf3_output_stream_delegate.cpp asymsecurefile/internal/jasf3/jasf3_output_stream_delegate.hpp asymsecurefile/internal/jasf3/raw_chunk.hpp asymsecurefile/internal/jasf3/raw_user_chunk.hpp asymsecurefile/internal/jasf3/reading_chunk.cpp asymsecurefile/internal/jasf3/reading_chunk.hpp asymsecurefile/internal/jasf3/seed_key_check_chunk.hpp asymsecurefile/internal/output_stream_delegate.hpp asymsecurefile/internal/signature_header.cpp asymsecurefile/internal/signature_header.hpp asymsecurefile/internal/version_router.cpp asymsecurefile/internal/version_router.hpp asymsecurefile/invalid_file_exception.hpp asymsecurefile/io_exception.hpp asymsecurefile/memstream.hpp asymsecurefile/net_support_algorithm_exception.hpp asymsecurefile/not_support_version_exception.hpp asymsecurefile/operation_type.cpp asymsecurefile/operation_type.hpp asymsecurefile/result.hpp asymsecurefile/user_chunk.hpp asymsecurefile/validate_failed_exception.hpp)
target_link_libraries(asymsecurefile jcp)

add_subdirectory(example)

find_package(MbedCrypto REQUIRED)
message("MBEDCRYPTO_LIBRARIES : ${MBEDCRYPTO_LIBRARIES}")
if(MBEDCRYPTO_FOUND  AND  MBEDCRYPTO_INCLUDE_DIR  AND  MBEDCRYPTO_LIBRARIES)
    add_definitions(-DJCP_USE_MBEDCRYPTO=1 -DHAS_MBEDTLS=1)
    include_directories(${MBEDCRYPTO_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${MBEDCRYPTO_LIBRARIES})
    set(_MBEDCRYPTO_VERSION_ ${MBEDCRYPTO_VERSION})
    message("-- mbedTLS ${MBEDCRYPTO_VERSION} found!")

    include_directories(${CMAKE_SOURCE_DIR}/provider/mbedcrypto/src/)
else()
    message("-- mbedTLS not found!")
    return()
endif()
