/**
 * @file	asym_algorithm_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <stdint.h>

#include <asymsecurefile/chunk.hpp>
#include "jasf3_chunk_type.hpp"
#include "algorithm_info.hpp"

#include "../byte_buffer.hpp"

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class AsymAlgorithmChunk : public Chunk
			{
			private:
				AlgorithmInfo algorithm_info_;

			public:
				enum common {
					CHUNK_TYPE = ASYM_ALGORITHM
				};

				AsymAlgorithmChunk(uint16_t data_size, const unsigned char* data)
                        : Chunk(CHUNK_TYPE, 0, data_size, data)
                {
					ByteBuffer byteBuffer(data, data_size);
					uint8_t keyType = byteBuffer.getUint8();
					uint16_t keySize = byteBuffer.getUint16();

					std::vector<const AsymAlgorithm*> asym_algorithms = AsymAlgorithm::values();
					for (auto iter = asym_algorithms.cbegin(); iter != asym_algorithms.cend(); iter++)
					{
						const AsymAlgorithm* item = *iter;
						if (item->getKeyType() == keyType)
						{
							algorithm_info_.set(item, keySize);
							break;
						}
					}
				}

				const AlgorithmInfo& getAlgorithmInfo() const
				{
					return algorithm_info_;
				}
			};

		} // namesppace jasf3

	} // namespace internal

} // namespace src
