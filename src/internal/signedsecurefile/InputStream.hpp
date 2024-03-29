/**
 * @file	InputStream.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	InputStream
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <string>

#include "AbstructSignedSecureFile.hpp"
#include "../../../jcp/asym_key_impl.hpp"
#include "Header.hpp"
#include "Buffer.hpp"

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/hmac.h>
#include <openssl/aes.h>
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
#include <mbedtls/cipher.h>
#include <openssl/aes.h>
#endif

namespace asymsecurefile {
    namespace internal {
        namespace signedsecurefile {

            class InputStream : public AbstructSignedSecureFile {
            private:
#if defined(HAS_OPENSSL) && HAS_OPENSSL
                HMAC_CTX *dataHmacCtx;
                HMAC_CTX *dataKeyHmacCtx;
                EVP_CIPHER_CTX *dataEvpCtx;
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
                mbedtls_md_context_t mbed_dataHmacCtx;
                mbedtls_md_context_t mbed_dataKeyHmacCtx;
                mbedtls_cipher_context_t mbed_dataCipher;
#endif

                bool useCppThrow;

                Buffer buffer;
                Header header;
                bool headerReaded;

                Buffer decryptedDataBuffer;

            public:
                InputStream(jcp::AsymKey *pubKey, const std::string &secretKey);

                ~InputStream();

                int input(const unsigned char *payload, size_t size,
                          exception::SignedSecureFileException *exception = NULL);

                int done(exception::SignedSecureFileException *exception = NULL);

                int read(unsigned char *buffer, size_t size);
            };

        }
    }
}