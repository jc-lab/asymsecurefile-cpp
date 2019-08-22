/**
 * @file	input_stream_delegate_impl.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "../input_stream_delegate.hpp"
#include "../../chunk.hpp"
#include "../../user_chunk.hpp"

#include <memory>

#include <jcp/asym_key.hpp>
#include <jcp/cipher.hpp>
#include <jcp/message_digest.hpp>
#include <jcp/mac.hpp>

#include <map>
#include <deque>
#include <mutex>
#include <asymsecurefile/data_algorithm.hpp>

#include "reading_chunk.hpp"
#include "algorithm_info.hpp"

namespace asymsecurefile
{

    namespace internal {

        namespace jasf3 {

            class DefaultHeaderChunk;

            class InputStreamDelegateImpl : public InputStreamDelegate {
			private:
				class DataChunkQueueItem;

				enum State {
					STATE_READ_HEADER,
					STATE_READ_DATA,
					STATE_READ_FOOTER,
					STATE_READ_DONE
				};

				std::istream* is_;

				std::map<uint32_t, std::unique_ptr<Chunk> > raw_chunk_map_;

				std::map<uint16_t, std::unique_ptr<UserChunk> > cached_user_chunk_map_;
				bool cached_user_chunks_;

				std::vector<unsigned char> auth_key_;
				std::vector<unsigned char> auth_tag_;

				std::vector<unsigned char> auth_enc_key_;

				AlgorithmInfo algorithm_info_;

				const jcp::AsymKey *asym_key_;
                std::unique_ptr<jcp::AsymKey> local_pubkey_;

				ReadingChunk reading_chunk_;

				State state_;
				std::deque< std::unique_ptr<DataChunkQueueItem> > cipher_data_queue_;
				std::deque< std::unique_ptr<DataChunkQueueItem> > plain_data_queue_;

				const DefaultHeaderChunk* default_header_chunk_;
				std::vector<unsigned char> mac_key_;

				bool footer_validated_;
				std::unique_ptr<jcp::MessageDigest> fingerprint_digest_;
				std::unique_ptr<jcp::Cipher> data_cipher_;
				std::unique_ptr<jcp::Mac> data_mac_;

				bool basic_inited_;
				bool read_prepared_;

			public:
				InputStreamDelegateImpl(std::istream *is);
				~InputStreamDelegateImpl();
                Result<void> setAuthKey(const unsigned char *auth_key, size_t length) override;
                Result<int> headerRead() override;
			private:
                Result<int> readPayload(State run_state, bool blocking);
                std::unique_ptr<std::exception> initBasic();
				bool prepareReadData(Result<int>& result);
                Result<void> verifySignData(const std::vector<unsigned char>& signature, const jcp::Buffer &fingerprint);
				std::unique_ptr< std::exception > validateFooter();

				template<class T>
				const T* getSpecialChunk() const;

                std::unique_ptr< std::exception > parseUserChunks();

            public:
                void setAsymKey(const jcp::AsymKey *key) override;

                Result<int> available() override;

                Result<int> read(unsigned char *buffer, size_t size) override;

                Result<std::vector<const UserChunk *>> userChunks() override;

                Result<const UserChunk *> getUserChunk(uint16_t code) override;

                bool isDataReadable() override;

                bool validate() override;


            private:
                std::unique_ptr<jcp::Cipher> createDataCipher(const DataAlgorithm *dataAlgorithm, const std::vector<unsigned char>& dataIV, const std::vector<unsigned char>& key, const std::vector<unsigned char>& authKey);
                std::unique_ptr<jcp::Cipher> createChunkCipher(const std::vector<unsigned char>& dataIV, const std::vector<unsigned char>& key, const std::vector<unsigned char>& authKey);
            };

        } // namesppace jasf3

    } // namespace internal

} // namespace asymsecurefile
