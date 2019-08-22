/**
 * @file	footer_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <asymsecurefile/chunk.hpp>
#include "jasf3_chunk_type.hpp"

#include "../byte_buffer.hpp"

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class FooterChunk : public Chunk
			{
			private:
				/*
				 * 0x01 FINGER_PRINT_SIZE(2byte, little endian)
				 * FINGER_PRINT
				 * 0x02 FINGER_PRINT_SIZE(2byte, little endian)
				 * SIGNATURE
				 * 0x03 MAC_SIZE(2byte, little endian)
				 * MAC
				 * 0x00
				 * FooterChunk SIZE (2byte)
				 * TOTAL_FILE_SIZE (8bytes, little endian)
				 */
				std::vector<unsigned char> fingerprint_;
				std::vector<unsigned char> signature_;
				std::vector<unsigned char> mac_;
				uint16_t footer_size_;
				uint64_t total_file_size_;
				uint64_t total_file_size_without_footer_;

			public:
				enum common {
					CHUNK_TYPE = FOOTER_FINGERPRINT
				};

				FooterChunk(uint16_t data_size, const unsigned char* data)
                        : Chunk(CHUNK_TYPE, 0, data_size, data)
                {
                    ByteBuffer byteBuffer(data, data_size);
					uint8_t type;

					do {
						type = byteBuffer.getUint8();
						if (type > 0) {
							short size = byteBuffer.getUint16();
							switch (type) {
							case 0x01:
							    fingerprint_.resize(size);
								byteBuffer.get(&fingerprint_[0], size);
								break;
							case 0x02:
                                signature_.resize(size);
                                byteBuffer.get(&signature_[0], size);
								break;
							case 0x03:
                                mac_.resize(size);
                                byteBuffer.get(&mac_[0], size);
								break;
							}
						}
					} while (type > 0);
					footer_size_ = byteBuffer.getUint16();
					total_file_size_ = byteBuffer.getUint64();
					total_file_size_without_footer_ = data_size;
				}

                const std::vector<unsigned char> &fingerprint() const {
                    return fingerprint_;
                }

                const std::vector<unsigned char> &signature() const {
                    return signature_;
                }

                const std::vector<unsigned char> &mac() const {
                    return mac_;
                }

                uint16_t footer_size() const {
                    return footer_size_;
                }

                uint64_t total_file_size() const {
                    return total_file_size_;
                }

                uint64_t total_file_size_without_footer() const {
                    return total_file_size_without_footer_;
                }
            };

		} // namesppace jasf3

	} // namespace internal

} // namespace src
