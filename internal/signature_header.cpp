/**
 * @file	signature_header.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "signature_header.hpp"
#include "../invalid_file_exception.hpp"

namespace asymsecurefile
{

    namespace internal {
        std::unique_ptr< Result<int> > SignatureHeader::read(std::unique_ptr< asymsecurefile::Result<int> > &result, const uint8_t *data) {
			static const uint8_t SIGNATURE[] = { 0x0a, 0x9b, 0xd8, 0x13, 0x97, 0x1f, 0x93, 0xe8, 0x6b, 0x7e, 0xdf, 0x05, 0x70, 0x54, 0x02 };
			if (memcmp(data, SIGNATURE, 15) != 0)
				return std::unique_ptr<Result<int>>(ResultBuilder<int, InvalidFileException>(-1).withException().build());
			version_ = data[15];
			return std::unique_ptr<Result<int>>(ResultBuilder<int, void>(0).build());
        }

        uint8_t SignatureHeader::version() const {
            return version_;
        }
    }

}
