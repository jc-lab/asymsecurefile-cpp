/**
 * @file	jasf3_chunk_resolver.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <memory>
#include <typeinfo>
#include <map>
#include <string>

#include <asymsecurefile/chunk.hpp>
#include "raw_user_chunk.hpp"

namespace asymsecurefile {

    namespace internal {

        namespace jasf3 {

			class Jasf3ChunkResolver {
			private:
				struct ChunkInfo {
					std::string cls_name_;

					ChunkInfo(const char * cls_name)
						: cls_name_(cls_name)
					{
					}

					const std::string &cls_name() const {
						return cls_name_;
					}

					bool compare_cls_name(const char* target) const {
						return (cls_name_ == target);
					}

					virtual std::unique_ptr<Chunk> create(uint16_t data_size, const unsigned char *data) const = 0;
				};

				template<class T>
				struct ChunkInfoImpl : ChunkInfo {
					ChunkInfoImpl(const char* cls_name)
						: ChunkInfo(cls_name)
					{
					}

					std::unique_ptr<Chunk> create(uint16_t data_size, const unsigned char *data) const override {
						return std::unique_ptr<Chunk>(new T(data_size, data));
					}
				};

				static std::map<uint8_t, std::unique_ptr<ChunkInfo> > chunk_types_;

				template<class T>
				static void addChunkType() {
					chunk_types_[T::CHUNK_TYPE] = std::unique_ptr<ChunkInfo>(new ChunkInfoImpl<T>(typeid(T).raw_name()));
				}

				struct StaticInitializer {
					StaticInitializer();
				};

				static StaticInitializer si_;

			public:
				static std::unique_ptr<Chunk> parseChunk(uint8_t primary_type, uint16_t user_code, uint16_t data_size, const unsigned char* data)
				{
					if ((primary_type & 0x80) != 0)
					{
						return std::unique_ptr<Chunk>(new RawUserChunk(primary_type, user_code, data_size, data));
					} else {
						std::map<uint8_t, std::unique_ptr<ChunkInfo> >::const_iterator found_iter = chunk_types_.find(primary_type);
						if (found_iter != chunk_types_.end())
						{
							return found_iter->second->create(data_size, data);
						}
					}
					return NULL;
				}
			};

        } // namesppace jasf3

    } // namespace internal

} // namespace src
