/**
 * @file	jasf3_chunk_resolver.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "jasf3_chunk_resolver.hpp"

#include "default_header_chunk.hpp"
#include "asym_algorithm_chunk.hpp"
#include "data_algorithm_chunk.hpp"
#include "encrypted_seed_key_chunk.hpp"
#include "seed_key_check_chunk.hpp"
#include "data_iv_chunk.hpp"
#include "footer_chunk.hpp"


namespace asymsecurefile {

	namespace internal {

		namespace jasf3 {

            std::map<uint8_t, std::unique_ptr<Jasf3ChunkResolver::ChunkInfo> > Jasf3ChunkResolver::chunk_types_;

			Jasf3ChunkResolver::StaticInitializer Jasf3ChunkResolver::si_;

			Jasf3ChunkResolver::StaticInitializer::StaticInitializer()
			{
				addChunkType<DefaultHeaderChunk>();
				addChunkType<AsymAlgorithmChunk>();
				addChunkType<DataAlgorithmChunk>();
				addChunkType<EncryptedSeedKeyChunk>();
				addChunkType<SeedKeyCheckChunk>();
				addChunkType<DataIvChunk>();
				addChunkType<FooterChunk>();
			}

		}

	}

}
