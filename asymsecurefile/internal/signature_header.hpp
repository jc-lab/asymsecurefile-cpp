/**
 * @file	signature_header.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <memory>
#include <stdint.h>
#include "../result.hpp"

namespace asymsecurefile
{

    namespace internal {

        class SignatureHeader {
        private:
            uint8_t version_;

        public:
            static int SIGNATURE_SIZE() {
                return 16;
            }

            Result<int> read(Result<int> &result, const uint8_t *data);

            uint8_t version() const;

        }; // class SignatureHeader

    } // class internal

} // namespace asymsecurefile
