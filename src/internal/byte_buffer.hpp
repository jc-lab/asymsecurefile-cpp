/**
 * @file	byte_buffer.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <stdint.h>
#include <string.h>

namespace asymsecurefile {

    namespace internal {

        class ByteBuffer
        {
        private:
            const unsigned char *buffer_;
            size_t pos_;
            size_t limit_;

            bool flowed_;

            bool check_flow(int size);

        public:
            ByteBuffer(const unsigned char *buffer, size_t size);
            bool flowed() const;
            uint8_t getUint8();
            uint16_t getUint16();
            uint32_t getUint32();
            uint64_t getUint64();
            bool get(unsigned char *outbuf, size_t len);

        }; // class ByteBuffer

    } // namespace internal

} // namespace src
