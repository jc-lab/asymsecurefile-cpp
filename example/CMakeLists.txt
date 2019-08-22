cmake_minimum_required(VERSION 3.4)
project(asf_example)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 11)

add_executable(asf_example example.cpp)

target_link_libraries(asf_example jcp)
target_link_libraries(asf_example asymsecurefile)

find_package(MbedCrypto REQUIRED)
message("MBEDCRYPTO_LIBRARIES : ${MBEDCRYPTO_LIBRARIES}")
if(MBEDCRYPTO_FOUND  AND  MBEDCRYPTO_INCLUDE_DIR  AND  MBEDCRYPTO_LIBRARIES)
    add_definitions(-DJCP_USE_MBEDCRYPTO=1)
    include_directories(${MBEDCRYPTO_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${MBEDCRYPTO_LIBRARIES})
    set(_MBEDCRYPTO_VERSION_ ${MBEDCRYPTO_VERSION})
    message("-- mbedTLS ${MBEDCRYPTO_VERSION} found!")

    target_link_libraries(asf_example jcp_provider_mbedcrypto)
else()
    message("-- mbedTLS not found!")
    return()
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    add_definitions(-DJCP_USE_OPENSSL=1)
    target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
    add_definitions(-DHAS_OPENSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
    message("-- OpenSSL ${OPENSSL_VERSION} found!")

    target_link_libraries(asf_example jcp_provider_openssl)
else()
    message("-- OpenSSL not found!")
    return()
endif()

target_link_libraries(asf_example ${EXTRA_LIBS})

include_directories(${CMAKE_SOURCE_DIR}/jcp/include)
include_directories(${CMAKE_SOURCE_DIR})
