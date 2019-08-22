/**
 * @file	data_iv_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "../../chunk.hpp"
#include "jasf3_chunk_type.hpp"

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class DataIvChunk : public Chunk
			{
			private:
			    std::vector<unsigned char> iv_;

			public:
				enum common {
					CHUNK_TYPE = DATA_IV
				};

				DataIvChunk(uint16_t data_size, const unsigned char* data)
				    : Chunk(CHUNK_TYPE, 0, data_size, data)
                {
                    iv_.insert(iv_.end(), data, data + data_size);
				}

				const std::vector<unsigned char>& iv() const {
				    return iv_;
				}
			};

		} // namesppace jasf3

	} // namespace internal

} // namespace asymsecurefile
