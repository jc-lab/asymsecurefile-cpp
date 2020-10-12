cmake_minimum_required(VERSION 3.4)
project(asymsecurefile)

include(FetchContent)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 11)

if(NOT TARGET jcp)
    message("Download jcp")

    FetchContent_Declare(
            jcp
            GIT_REPOSITORY https://github.com/jc-lab/jcp.git
            GIT_TAG        v0.0.1
    )

    FetchContent_GetProperties(jcp)

    if(NOT jcp_POPULATED)
        FetchContent_Populate(jcp)
        add_subdirectory(${jcp_SOURCE_DIR} ${jcp_BINARY_DIR})
    endif()
endif()

add_library(asymsecurefile src/asym_algorithm.cpp include/asymsecurefile/asym_algorithm.hpp src/chunk.cpp include/asymsecurefile/chunk.hpp src/data_algorithm.cpp include/asymsecurefile/data_algorithm.hpp src/frame.cpp include/asymsecurefile/frame.hpp src/input_stream.cpp include/asymsecurefile/input_stream.hpp src/internal/byte_buffer.cpp src/internal/byte_buffer.hpp include/asymsecurefile/internal/input_stream_delegate.hpp src/internal/jasf3/algorithm_info.hpp src/internal/jasf3/asym_algorithm_chunk.hpp src/internal/jasf3/data_algorithm_chunk.hpp src/internal/jasf3/data_iv_chunk.hpp src/internal/jasf3/default_header_chunk.hpp src/internal/jasf3/encrypted_seed_key_chunk.hpp src/internal/jasf3/footer_chunk.hpp src/internal/jasf3/jasf3_chunk_resolver.cpp src/internal/jasf3/jasf3_chunk_resolver.hpp src/internal/jasf3/jasf3_chunk_type.hpp src/internal/jasf3/jasf3_input_stream_delegate.cpp src/internal/jasf3/jasf3_input_stream_delegate.hpp src/internal/jasf3/jasf3_output_stream_delegate.cpp src/internal/jasf3/jasf3_output_stream_delegate.hpp src/internal/jasf3/raw_chunk.hpp src/internal/jasf3/raw_user_chunk.hpp src/internal/jasf3/reading_chunk.cpp src/internal/jasf3/reading_chunk.hpp src/internal/jasf3/seed_key_check_chunk.hpp include/asymsecurefile/internal/output_stream_delegate.hpp src/internal/signature_header.cpp include/asymsecurefile/internal/signature_header.hpp src/internal/version_router.cpp src/internal/version_router.hpp include/asymsecurefile/invalid_file_exception.hpp include/asymsecurefile/io_exception.hpp include/asymsecurefile/memstream.hpp include/asymsecurefile/net_support_algorithm_exception.hpp include/asymsecurefile/not_support_version_exception.hpp src/operation_type.cpp include/asymsecurefile/operation_type.hpp include/asymsecurefile/result.hpp include/asymsecurefile/user_chunk.hpp include/asymsecurefile/validate_failed_exception.hpp)
target_include_directories(asymsecurefile
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(asymsecurefile jcp)

add_subdirectory(example)

