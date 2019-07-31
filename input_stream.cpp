/**
 * @file	input_stream.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "input_stream.hpp"
#include "internal/version_router.hpp"
#include "internal/signature_header.hpp"
#include "invalid_file_exception.hpp"

namespace asymsecurefile
{

	InputStream::InputStream()
		: basic_istream(&sb_, false), header_read_result_readmore_(ResultBuilder<int, void>(1).build() /* Read More */), sb_(this)
	{
		is_ = NULL;
		signature_header_ready_ = false;
		signature_header_buf_.resize(SignatureHeader::SIGNATURE_SIZE());
		signature_header_buf_pos_ = 0;
	}

	InputStream::InputStream(std::istream *is)
		: basic_istream(&sb_, false), header_read_result_readmore_(ResultBuilder<int,void>(1).build() /* Read More */ ), sb_(this)
	{
		is_ = is;
		signature_header_ready_ = false;
        signature_header_buf_.resize(SignatureHeader::SIGNATURE_SIZE());
		signature_header_buf_pos_ = 0;
	}

	InputStream::~InputStream() {

	}

	void InputStream::setStream(std::istream *is) {
		is_ = is;
	}

    Result<int> *InputStream::headerRead() {
        if (!signature_header_ready_) {
            int remaining = SignatureHeader::SIGNATURE_SIZE() - signature_header_buf_pos_;
            is_->read((char *) &signature_header_buf_[signature_header_buf_pos_], remaining);
            signature_header_buf_pos_ += is_->gcount();
            if (signature_header_buf_pos_ == SignatureHeader::SIGNATURE_SIZE()) {
				std::unique_ptr< Result<int> > result = signature_header_.read(header_read_result_last_, signature_header_buf_.data());
                if(result->exception()) {
					header_read_result_last_ = std::move(result);
                    return header_read_result_last_.get();
                }

                VersionRouter::InputStreamDelegateFactory *factory = VersionRouter::findReaderDelegate(signature_header_.version());
                if(!factory) {
                    header_read_result_last_.reset(new ResultImpl<int, InvalidFileException>(-1));
                    return header_read_result_last_.get();
                }

                delegate_ = std::move(factory->create(is_));

                signature_header_ready_ = true;
            }
        }

        if (signature_header_ready_) {
			header_read_result_last_ = delegate_->headerRead();
			return header_read_result_last_.get();
        }

        return header_read_result_readmore_.get();
    }

    std::unique_ptr< Result<void> > InputStream::setAuthKey(const uint8_t *authKey, int length) {
        return delegate_->setAuthKey(authKey, length);
    }

    void InputStream::setAsymKey(const jcp::AsymKey *key) {
        return delegate_->setAsymKey(key);
    }

	std::unique_ptr<Result< const UserChunk* > > InputStream::getUserChunk(uint16_t code) {
		return delegate_->getUserChunk(code);
	}

    std::unique_ptr< Result< std::vector< const UserChunk* > > > InputStream::userChunks() {
        return delegate_->userChunks();
	}

    std::exception *InputStream::read_exception() {
        return read_exception_.get();
	}

    InputStream::InputStreamBuffer::int_type InputStream::InputStreamBuffer::underflow() {
        std::unique_ptr<Result<int>> result = parent_->delegate_->read(&gbuf_[0], gbuf_.capacity());
		if(result->exception())
	        parent_->read_exception_ = result->move_exception();
		if (result->result() > 0)
		{
			this->setg((char*)gbuf_.data(), (char*)gbuf_.data(), (char*)gbuf_.data() + result->result());
			return gbuf_[0];
		}
        return traits_type::eof();
    }
}
