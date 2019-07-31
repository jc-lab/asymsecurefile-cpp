/**
 * @file	raw_user_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "../../user_chunk.hpp"
#include "jasf3_chunk_type.hpp"

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class RawUserChunk : public UserChunk
			{
			public:
                RawUserChunk(uint8_t flag, uint16_t usercode, uint16_t data_size, const unsigned char* data)
                        : UserChunk(flag | 0x80, usercode, data_size, data)
                {
                }

                RawUserChunk(const RawUserChunk *obj)
                        : UserChunk(obj->primary_type_, obj->user_code_, obj->data_size_, obj->data_.data())
                {
                }
			};

		} // namesppace jasf3

	} // namespace internal

} // namespace asymsecurefile
