/**
 * @file	user_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <vector>
#include <stdint.h>

#include "chunk.hpp"

namespace asymsecurefile
{
	class UserChunk : public Chunk
	{
	public:
		UserChunk(uint8_t flag, uint16_t user_code, uint16_t data_size, const unsigned char* data)
			: Chunk(0x80 | flag, user_code, data_size, data)
		{
			
		}

		const Flag* getFlag() const {
			std::vector<const Chunk::Flag*> flags = Flag::values();
			uint8_t flag_value = primary_type_ & 0x7F;
			for (std::vector<const Chunk::Flag*>::const_iterator iter = flags.cbegin(); iter != flags.cend(); iter++)
			{
				if (flag_value == (*iter)->getValue())
				{
					return (*iter);
				}
			}
			return NULL;
		}

		uint16_t getUserCode() const {
			return user_code_;
		}
	}; // class Chunks

} // namespace asymsecurefile
