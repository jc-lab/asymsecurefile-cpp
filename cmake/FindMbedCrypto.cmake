# Try to find mbedTLS's Crypto library
#
# Once done this will define
# MBEDCRYPTO_FOUND
# MBEDCRYPTO_INCLUDE_DIR
# MBEDCRYPTO_LIBRARIES
# MBEDCRYPTO_VERSION_MAJOR
# MBEDCRYPTO_VERSION_MINOR
# MBEDCRYPTO_VERSION_PATCH
# MBEDCRYPTO_VERSION

include(FindPackageHandleStandardArgs)
find_path(MBEDCRYPTO_INCLUDE_DIR NAMES mbedtls/ssl.h)

find_library(MBEDCRYPTO_LIB NAMES mbedcrypto)
find_package_handle_standard_args(MBEDCRYPTO REQUIRED_VARS MBEDCRYPTO_INCLUDE_DIR MBEDCRYPTO_LIB)

if( ${MBEDCRYPTO_LIBRARIES-NOTFOUND} )
    message(FATAL_ERROR "Failed to get info from Mbedtls library, check your Mbedtls installation")
    set(MBEDCRYPTO_FOUND False)
    return()
endif()

if(NOT DEFINED ${MBEDX509_LIB})
    set(MBEDX509_LIB ${MBEDCRYPTO_LIB})
endif()

if(NOT DEFINED ${MBEDX509_INCLUDE_DIR})
    set(MBEDX509_INCLUDE_DIR ${MBEDCRYPTO_INCLUDE_DIR})
endif()

find_library(MBEDX509_LIB NAMES mbedcrypto)
find_package_handle_standard_args(MBEDX509 REQUIRED_VARS MBEDX509_INCLUDE_DIR MBEDX509_LIB)

if( ${MBEDX509_LIBRARIES-NOTFOUND} )
    message(FATAL_ERROR "Failed to get info from Mbedtls library, check your Mbedtls installation")
    set(MBEDX509_FOUND False)
    return()
endif()

#execute_process(
#        COMMAND bash -c "echo \"#include <mbedtls/version.h>\n#include <stdio.h>\nint main(){printf(MBEDTLS_VERSION_STRING);return 0;}\">a.c;cc a.c -I${MBEDCRYPTO_INCLUDE_DIR} ${MBEDCRYPTO_LIBRARIES} ;./a.out;rm -f a.c a.out"
#        OUTPUT_VARIABLE MBEDCRYPTO_VERSION
#)
#
#string(REPLACE "." ";" MBEDCRYPTO_VERSION_LIST ${MBEDCRYPTO_VERSION})
#
#list(GET ${MBEDCRYPTO_VERSION_LIST} 0 MBEDCRYPTO_VERSION_MAJOR)
#list(GET ${MBEDCRYPTO_VERSION_LIST} 1 MBEDCRYPTO_VERSION_MINOR)
#list(GET ${MBEDCRYPTO_VERSION_LIST} 2 MBEDCRYPTO_VERSION_PATCH)
#
#if( ${MBEDCRYPTO_VERSION} VERSION_LESS "2.1.0")
#    message(FATAL_ERROR "Mbedtls 2.1+ is required for compiling ${PROGNAME} (current is ${MBEDCRYPTO_VERSION}).")
#    set(MBEDCRYPTO_FOUND False)
#    return()
#endif()

set(MBEDCRYPTO_LIBRARIES ${MBEDX509_LIB}/mbedx509.lib ${MBEDCRYPTO_LIB}/mbedcrypto.lib)

set(MBEDCRYPTO_FOUND True)
mark_as_advanced(
        MBEDCRYPTO_FOUND
        MBEDCRYPTO_INCLUDE_DIR
        MBEDCRYPTO_LIBRARIES
        MBEDCRYPTO_VERSION_MAJOR
        MBEDCRYPTO_VERSION_MINOR
        MBEDCRYPTO_VERSION_PATCH
        MBEDCRYPTO_VERSION
)