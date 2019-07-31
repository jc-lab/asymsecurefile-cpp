/**
 * @file	seed_key_check_chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "../../chunk.hpp"
#include "jasf3_chunk_type.hpp"

#include <jcp/secret_key_factory.hpp>
#include <jcp/secret_key_factory_algo.hpp>
#include <jcp/pbe_key_spec.hpp>

namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

			class SeedKeyCheckChunk : public Chunk
			{
			private:
                std::vector<unsigned char> salt_;
                std::vector<unsigned char> encoded_;

			public:
				enum common {
					CHUNK_TYPE = SEED_KEY_CHECK,
                    SALT_SIZE = 16,
                    PASS_SIZE = 16
				};

                SeedKeyCheckChunk(uint16_t data_size, const unsigned char* data)
                        : Chunk(CHUNK_TYPE, 0, data_size, data)
                {
                    if(data_size < (SALT_SIZE + PASS_SIZE))
                        return ;

                    salt_.insert(salt_.end(), &data[0], &data[SALT_SIZE]);
                    salt_.insert(salt_.end(), &data[SALT_SIZE], &data[SALT_SIZE + PASS_SIZE]);
				}

				bool verify(const std::vector<unsigned char>& plain_key) const {
                    const jcp::SecretKeyFactory *skf = jcp::SecretKeyFactory::getInstance(jcp::SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA256.algo_id());
					jcp::PBEKeySpec key_spec((const char*)plain_key.data(), plain_key.size(), salt_.data(), salt_.size(), 1000, PASS_SIZE * 8);
					std::unique_ptr<jcp::Result<jcp::SecretKey>> result = skf->generateSecret(&key_spec);
                    if(result->exception())
                        return false;
                    const std::vector<unsigned char>& encoded = result->result().getEncoded();
                    if(encoded.size() != encoded_.size())
                        return false;
                    if(memcmp(encoded.data(), encoded_.data(), encoded.size()))
                        return false;
                    return true;
                }
			};

		} // namesppace jasf3

	} // namespace internal

} // namespace asymsecurefile
