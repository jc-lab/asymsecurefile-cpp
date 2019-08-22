/**
 * @file	jasf3_chunk_type.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

namespace asymsecurefile
{

    namespace internal {

        namespace jasf3 {

			enum Jasf3ChunkType {
				DEFAULT_HEADER = 0x01,
				ASYM_ALGORITHM = 0x02,
				DATA_ALGORITHM = 0x03,
				ENCRYPTED_SEED_KEY = 0x04,
				DATA_IV = 0x11,
				DATA_STREAM = 0x70,
				FOOTER_FINGERPRINT = 0x7A
			};

        } // namesppace jasf3

    } // namespace internal

} // namespace src
