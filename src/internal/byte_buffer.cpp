/**
 * @file	byte_buffer.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "byte_buffer.hpp"

namespace asymsecurefile {

    namespace internal {

        bool ByteBuffer::check_flow(int size) {
            if((pos_ + size) > limit_) {
                flowed_ = true;
            }
            return flowed_;
        }

        // wrap
        ByteBuffer::ByteBuffer(const unsigned char *buffer, size_t size)
                : buffer_(buffer), pos_(0), limit_(size), flowed_(false)
        {
        }

        bool ByteBuffer::flowed() const {
            return flowed_;
        }

        uint8_t ByteBuffer::getUint8() {
            if(check_flow(sizeof(uint8_t)))
                return 0;
            uint8_t value = *((const uint8_t*)&buffer_[pos_]);
            pos_ += sizeof(uint8_t);
            return value;
        }

        uint16_t ByteBuffer::getUint16() {
            if(check_flow(sizeof(uint16_t)))
                return 0;
            uint16_t value = *((const uint16_t*)&buffer_[pos_]);
            pos_ += sizeof(uint16_t);
            return value;
        }

        uint32_t ByteBuffer::getUint32() {
            if(check_flow(sizeof(uint32_t)))
                return 0;
            uint32_t value = *((const uint32_t*)&buffer_[pos_]);
            pos_ += sizeof(uint32_t);
            return value;
        }

        uint64_t ByteBuffer::getUint64() {
            if(check_flow(sizeof(uint64_t)))
                return 0;
            uint64_t value = *((const uint64_t*)&buffer_[pos_]);
            pos_ += sizeof(uint64_t);
            return value;
        }

        bool ByteBuffer::get(unsigned char *outbuf, size_t len) {
            if(check_flow(len))
                return false;
            memcpy(outbuf, &buffer_[pos_], len);
			pos_ += len;
            return true;
        }

        bool ByteBuffer::skip(size_t len) {
            if(check_flow(len))
                return false;
            pos_ += len;
            return true;
        }

    } // namespace internal

} // namespace src
