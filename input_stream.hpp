/**
 * @file	input_stream.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <istream>
#include <memory>
#include <list>
#include <vector>

#include "result.hpp"
#include "internal/signature_header.hpp"
#include "internal/input_stream_delegate.hpp"

namespace jcp {
	class AsymKey;
}

namespace asymsecurefile
{
    using namespace internal;

    class UserChunk;

    class InputStream : public std::istream
	{
	private:

		class InputStreamBuffer : public std::streambuf {
		private:
            InputStream *parent_;
            std::vector<unsigned char> gbuf_;
		public:
            InputStreamBuffer(InputStream *parent) : parent_(parent), gbuf_(4096) {}
        protected:
            int_type underflow() override;
        };

		std::istream* is_;
		InputStreamBuffer sb_;
		std::unique_ptr<InputStreamDelegate> delegate_;

        SignatureHeader signature_header_;
        bool            signature_header_ready_;
        std::vector<uint8_t> signature_header_buf_;
        int                  signature_header_buf_pos_;

		std::unique_ptr< Result<int> > header_read_result_readmore_;
		std::unique_ptr< Result<int> > header_read_result_last_;
        std::unique_ptr< std::exception > read_exception_;

	public:
		InputStream();
		InputStream(std::istream* is);
        ~InputStream() override;

		void setStream(std::istream* is);

		/**
		 * header read with Shared Result
		 *
         * @return The following return values can occur:
         *         0 : Header reading is complete. The data is ready to be read.
         *         1 : Need more header reads.
         *         -1 : Error (result.exception() != NULL)
		 */
		Result<int>* headerRead();

		/***
		 * Set authKey
		 *
		 * @param authKey
		 * @param length
		 */
        std::unique_ptr< Result<void> > setAuthKey(const uint8_t *authKey, int length);

		/**
		 * Set Asymmetric jcp::AsymKey (jcp::AsymKey class)
		 *
		 * @param key
		 */
		void setAsymKey(const jcp::AsymKey *key);

        std::unique_ptr<Result< const UserChunk* > > getUserChunk(uint16_t code);

		std::unique_ptr< Result< std::vector< const UserChunk* > > > userChunks();

		/**
		 *
		 * @return Returns the last exception that occurred, if any.
		 */
		std::exception *read_exception();


        std::unique_ptr< Result<void> > setAuthKey(const std::string& authKey) {
            return setAuthKey((const uint8_t*)authKey.c_str(), authKey.length());
        }

    protected:
    }; // class InputStream

} // namespace asymsecurefile
