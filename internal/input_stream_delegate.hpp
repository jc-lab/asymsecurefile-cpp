/**
 * @file	input_stream_delegate.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <memory>
#include <istream>

#include <jcp/asym_key.hpp>

#include "../user_chunk.hpp"
#include "../result.hpp"

namespace asymsecurefile
{

    namespace internal {

        class InputStreamDelegate
        {
        public:
            virtual void setAsymKey(const jcp::AsymKey *key) = 0;
            virtual std::unique_ptr< Result<void> > setAuthKey(const unsigned char *auth_key, size_t length) = 0;

			virtual std::unique_ptr< Result<int> > headerRead() = 0;
			virtual std::unique_ptr< Result<int> > available() = 0;
			virtual std::unique_ptr< Result<int> > read(unsigned char *buffer, size_t size) = 0;
            virtual std::unique_ptr<Result<std::vector<const UserChunk *>>> userChunks() = 0;
            virtual std::unique_ptr<Result<const UserChunk *>> getUserChunk(uint16_t code) = 0;
			virtual bool isDataReadable() = 0;
			virtual bool validate() = 0;
        };

    } // namespace internal

} // namespace asymsecurefile
