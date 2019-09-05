/**
 * @file	default_header_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <asymsecurefile/chunk.hpp>
#include <asymsecurefile/operation_type.hpp>
#include "jasf3_chunk_type.hpp"

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class DefaultHeaderChunk : public Chunk
			{
			private:
                const OperationType* operation_type_;
                std::vector<unsigned char> seed_;

			public:
				enum common {
					CHUNK_TYPE = DEFAULT_HEADER
				};

				DefaultHeaderChunk(uint16_t data_size, const unsigned char* data)
				    : Chunk(CHUNK_TYPE, 0, data_size, data)
				{
					operation_type_ = OperationType::valueOf(data[0]);
                    seed_.insert(seed_.end(), &data[0], &data[16]);
				}

				const OperationType *operation_type() const {
				    return operation_type_;
				}

				const std::vector<unsigned char>& seed() const {
				    return seed_;
				}
			};

		} // namesppace jasf3

	} // namespace internal

} // namespace src
