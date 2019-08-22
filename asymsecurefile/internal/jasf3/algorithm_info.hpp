/**
 * @file	algorithm_info.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "../../asym_algorithm.hpp"
#include <jcp/asym_key.hpp>

namespace asymsecurefile {

    namespace internal {

        namespace jasf3 {

			class AlgorithmInfo {
			private:
				const AsymAlgorithm* asym_algo_;
				int key_size_;

			public:
				AlgorithmInfo() {}
				AlgorithmInfo(const AlgorithmInfo& src)
				: asym_algo_(src.asym_algo_), key_size_(src.key_size_)
				{
				}

				void find(const jcp::AsymKey* key, const AsymAlgorithm* asym_algo)
				{
					asym_algo_ = asym_algo;
					if (!asym_algo_) {
						std::vector<const AsymAlgorithm*> algos = AsymAlgorithm::values();
						for (auto iter = algos.cbegin(); iter != algos.cend(); iter++)
						{
							// Compare OID
						}
					}
				}

				void set(const AsymAlgorithm* asym_algo, int key_size) {
					asym_algo_ = asym_algo;
					key_size_ = key_size;
				}

                const AsymAlgorithm *getAlgorithmPtr() const {
                    return asym_algo_;
                }

            };

        } // namesppace jasf3

    } // namespace internal

} // namespace asymsecurefile
