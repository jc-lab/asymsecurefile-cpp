/**
 * @file	reading_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <istream>
#include <jcp/message_digest.hpp>
#include "../../result.hpp"

namespace asymsecurefile
{

    namespace internal {

        namespace jasf3 {

			class ReadingChunk {
			private:
				uint8_t primary_type_;
				uint16_t usercode_;
				uint16_t size_;
				int step_;

				std::vector<unsigned char> temp_buf_;
				std::vector<unsigned char> data_stream_;

			public:
				ReadingChunk();
				// -1 : error
				// 0 : more read
				// 1 : catched
				int read(std::unique_ptr< Result<int> >& result, std::istream *is, bool blocking, jcp::MessageDigest *fingerprint_digest);
				void reset() {
					step_ = 0;
					primary_type_ = 0;
					data_stream_.clear();
					data_stream_.reserve(4096);
				}

				uint8_t getPrimaryType() const {
					return primary_type_;
				}

				uint16_t getUserCode() const {
					return usercode_;
				}

				uint16_t getSize() const {
					return size_;
				}

				const unsigned char *getData() const {
				    return data_stream_.data();
				}
			};

        } // namesppace jasf3

    } // namespace internal

} // namespace asymsecurefile
