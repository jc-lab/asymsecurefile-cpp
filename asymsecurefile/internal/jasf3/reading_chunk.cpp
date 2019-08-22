/**
 * @file	reading_chunk.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "../../result.hpp"
#include "reading_chunk.hpp"
#include "jasf3_chunk_type.hpp"

#include "../../invalid_file_exception.hpp"

namespace asymsecurefile
{

    namespace internal {

        namespace jasf3 {

			ReadingChunk::ReadingChunk()
				: primary_type_(0), usercode_(0), size_(0), step_(0)
			{
				temp_buf_.resize(4096);
				data_stream_.reserve(4096);
			}

			int ReadingChunk::read(Result<int>& result, std::istream* is, bool blocking, jcp::MessageDigest* message_digest)
			{
				while ((is->rdbuf()->in_avail() > 0) || blocking) {
					int temp;
					switch (step_) {
					case 0:
						temp = is->get();
						if (temp < 0)
						{
							result = Result<int>(ResultBuilder<int, InvalidFileException>(0).withException().build());
							return -1;
						}
						primary_type_ = (unsigned char)temp;
						if (primary_type_ != FOOTER_FINGERPRINT)
							message_digest->update((unsigned char)temp);
						usercode_ = 0;
						size_ = 0;
						data_stream_.clear(); data_stream_.reserve(4096);
						if ((temp & 0x80) == 0)
							step_ = 3;
						else
							step_++;
						break;
					case 1:
					case 2:
						temp = is->get();
						if (temp < 0)
						{
							result = Result<int>(ResultBuilder<int, InvalidFileException>(0).withException().build());
							return -1;
						}
						if (primary_type_ != FOOTER_FINGERPRINT)
							message_digest->update((unsigned char)temp);
						usercode_ |= (temp & 0xFF) << ((step_ - 1) * 8);
						step_++;
						break;
					case 3:
					case 4:
						temp = is->get();
						if (temp < 0)
							if (temp < 0)
							{
								result = Result<int>(ResultBuilder<int, InvalidFileException>(0).withException().build());
								return -1;
							}
						if (primary_type_ != FOOTER_FINGERPRINT)
							message_digest->update((unsigned char)temp);
						size_ |= (temp & 0xFF) << ((step_ - 3) * 8);
						step_++;
						break;
					case 5:
						if (step_ <= 0) {
							char errmsg[256];
							sprintf_s(errmsg, "wrong chunk size (%d)", step_);
							result = Result<int>(ResultBuilder<int, InvalidFileException>(0).withException(errmsg).build());
							return -1;
						}
						if (data_stream_.size() < step_) {
							int remaining = size_ - data_stream_.size();
							int avail = is->rdbuf()->in_avail();
							avail = (remaining < avail) ? remaining : avail;
							avail = (avail < temp_buf_.size()) ? avail : temp_buf_.size();
							is->read((char*)&temp_buf_[0], avail);
							if (primary_type_ != FOOTER_FINGERPRINT)
								message_digest->update(temp_buf_.data(), avail);
							data_stream_.insert(data_stream_.end(), temp_buf_.data(), temp_buf_.data() + avail);
						}
						if (data_stream_.size() == size_) {
							return 1;
						}
						else if (data_stream_.size() > size_) {
							assert(false);
						}
						break;
					}
				}
				return 0;
			}

        } // namesppace jasf3

    } // namespace internal

} // namespace asymsecurefile
