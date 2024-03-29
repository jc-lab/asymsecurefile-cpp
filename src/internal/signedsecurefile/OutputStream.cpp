/**
 * @file	OutputStream.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	OutputStream
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "OutputStream.hpp"

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/opensslv.h>
#endif

namespace asymsecurefile {
    namespace internal {
        namespace signedsecurefile {

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
            static HMAC_CTX *HMAC_CTX_new(void)
            {
                HMAC_CTX *ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(*ctx));
                if (ctx != NULL)
                    HMAC_CTX_init(ctx);
                return ctx;
            }

            static void HMAC_CTX_free(HMAC_CTX *ctx)
            {
                if (ctx != NULL) {
                    HMAC_CTX_cleanup(ctx);
                    OPENSSL_free(ctx);
                }
            }

            static void HMAC_CTX_reset(HMAC_CTX *ctx)
            {
                HMAC_CTX_cleanup(ctx);
            }
#endif
#endif

            OutputStream::OutputStream(jcp::AsymKey *priKey, const std::string &secretKey,
                                       exception::SignedSecureFileException *exception) :
                    header(this) {
                unsigned char dataKey[32] = {0};
                unsigned int dataKeyLen = sizeof(dataKey);

                this->header.setAsymKey(priKey, true);
                this->header.generateKey();
                this->header.setDataCipherAlgorithm(DataCipherAlgorithm::AES);
#if defined(HAS_OPENSSL) && HAS_OPENSSL
                HMAC_CTX *dataKeyHmacCtx = HMAC_CTX_new();
                dataHmacCtx = HMAC_CTX_new();
                HMAC_Init_ex(dataKeyHmacCtx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
                HMAC_Init_ex(dataHmacCtx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
                HMAC_Update(dataKeyHmacCtx, this->header.secureHeader.key, sizeof(this->header.secureHeader.key));
                HMAC_Final(dataKeyHmacCtx, dataKey, &dataKeyLen);
                HMAC_CTX_free(dataKeyHmacCtx);
                dataEvpCtx = EVP_CIPHER_CTX_new();
                EVP_CipherInit_ex(dataEvpCtx, EVP_aes_256_cbc(), NULL, dataKey, Header::DATA_IV, 1);
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
                mbedtls_md_init(&mbed_dataHmacCtx);
                mbedtls_cipher_init(&mbed_dataCipher);
                mbedtls_md_setup(&mbed_dataHmacCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
                mbedtls_md_hmac_starts(&mbed_dataHmacCtx, (const unsigned char*)secretKey.c_str(), secretKey.length());
#endif
                this->computedHeaderSize = Header::COMMON_HEADER_SIZE + header.getSignedSecureHeaderSize();
                this->buffer.writeZero(this->computedHeaderSize);
            }

            OutputStream::~OutputStream() {
#if defined(HAS_OPENSSL) && HAS_OPENSSL
                if(dataHmacCtx)
                    HMAC_CTX_free(dataHmacCtx);
                if (dataEvpCtx)
                    EVP_CIPHER_CTX_free(dataEvpCtx);
#endif
            }

            int OutputStream::write(const unsigned char *buffer, size_t size) {
                jcp::AsymKey *asymKey = this->header.getAsymKey();
                const unsigned char *writePtr = buffer;
                size_t remaining = size;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
                if (asymKey->isOpensslKey()) {
                    int outLen;
                    HMAC_Update(dataHmacCtx, buffer, size);
                    this->header.secureHeader.datasize += size;
                    do {
                        int rc;
                        unsigned char out[256 + 32];
                        unsigned int writtenSize = remaining > 256 ? 256 : remaining;
                        outLen = 0;
                        rc = EVP_CipherUpdate(dataEvpCtx, out, &outLen, writePtr, writtenSize);
                        if (rc <= 0)
                        {
                            // Error
                            break;
                        }
                        remaining -= writtenSize;
                        writePtr += writtenSize;

                        if (outLen > 0)
                            this->buffer.write(out, outLen);
                    } while (remaining > 0);
                }
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
                if (asymKey->isMbedtlsKey()) {
                    size_t outLen;
                    mbedtls_md_hmac_update(&mbed_dataHmacCtx, buffer, size);
                    this->header.secureHeader.datasize += size;
                    do {
                        int rc;
                        unsigned char out[256 + 32];
                        unsigned int writtenSize = remaining > 256 ? 256 : remaining;
                        outLen = 0;
                        rc = mbedtls_cipher_update(&mbed_dataCipher, writePtr, writtenSize, out, &outLen);
                        if (rc != 0)
                        {
                            // Error
                            break;
                        }
                        remaining -= writtenSize;
                        writePtr += writtenSize;

                        if (outLen > 0)
                            this->buffer.write(out, outLen);
                    } while (remaining > 0);
                }
#endif
                return size;
            }

            int OutputStream::save(exception::SignedSecureFileException *exception) {
                jcp::AsymKey *asymKey = this->header.getAsymKey();
                unsigned char hmac[32];
                unsigned int hmacLen = sizeof(hmac);
                int rc;
                unsigned char out[256];
#if defined(HAS_OPENSSL) && HAS_OPENSSL
                if (asymKey->isOpensslKey()) {
                    int outLen;
                    outLen = sizeof(out);
                    rc = EVP_CipherFinal(dataEvpCtx, out, &outLen);
                    if (rc > 0)
                    {
                        if (outLen > 0)
                            this->buffer.write(out, outLen);
                    }
                    HMAC_Final(dataHmacCtx, hmac, &hmacLen);
                }
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
                if (asymKey->isMbedtlsKey()) {
                    size_t outLen;
                    outLen = sizeof(out);
                    rc = mbedtls_cipher_finish(&mbed_dataCipher, out, &outLen);
                    if (rc > 0)
                    {
                        if (outLen > 0)
                            this->buffer.write(out, outLen);
                    }
                    mbedtls_md_hmac_finish(&mbed_dataHmacCtx, hmac);
                }
#endif
                memcpy(header.secureHeader.hmac, hmac, hmacLen);
                if (header.writeTo(this->buffer, this->computedHeaderSize, exception)) {
                    return 0;
                }
                return -1;
            }
        }

    }
}
