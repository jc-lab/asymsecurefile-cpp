/**
 * @file	data_algorithm_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "../../chunk.hpp"
#include "jasf3_chunk_type.hpp"
#include "../../data_algorithm.hpp"

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class DataAlgorithmChunk : public Chunk
			{
			private:
			    const DataAlgorithm *data_algorithm_;

			public:
				enum common {
					CHUNK_TYPE = DATA_ALGORITHM
				};

				DataAlgorithmChunk(uint16_t data_size, const unsigned char* data)
                        : Chunk(CHUNK_TYPE, 0, data_size, data), data_algorithm_(NULL)
                {
                    const std::vector<const DataAlgorithm*> data_algorithms = DataAlgorithm::values();
                    for(auto iter = data_algorithms.cbegin(); iter != data_algorithms.cend(); iter++) {
                        const DataAlgorithm* item = (*iter);
                        if(item->getIdentifier().size() == data_size) {
                            if(memcmp(item->getIdentifier().data(), data, data_size) == 0) {
                                data_algorithm_ = item;
                                break;
                            }
                        }
                    }
				}

				const DataAlgorithm *dataAlgorithmPtr() const {
				    return data_algorithm_;
				}
			};

		} // namesppace jasf3

	} // namespace internal

} // namespace asymsecurefile
