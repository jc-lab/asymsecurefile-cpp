/**
 * @file	input_stream_delegate_impl.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "jasf3_input_stream_delegate.hpp"

#include "../../io_exception.hpp"
#include "../../invalid_file_exception.hpp"
#include "../../validate_failed_exception.hpp"

#include "jasf3_chunk_type.hpp"
#include "default_header_chunk.hpp"
#include "asym_algorithm_chunk.hpp"
#include "data_algorithm_chunk.hpp"
#include "data_iv_chunk.hpp"
#include "encrypted_seed_key_chunk.hpp"
#include "seed_key_check_chunk.hpp"
#include "footer_chunk.hpp"

#include "jasf3_chunk_resolver.hpp"

#include <jcp/mac.hpp>
#include <jcp/key_agreement.hpp>
#include <jcp/message_digest.hpp>
#include <jcp/message_digest_algo.hpp>
#include <jcp/mac_algo.hpp>
#include <jcp/key_agreement_algo.hpp>
#include <jcp/cipher_algo.hpp>
#include <jcp/gcm_param_spec.hpp>
#include <jcp/iv_param_spec.hpp>
#include <jcp/exception/aead_bad_tag.hpp>
#include <jcp/x509_encoded_key_spec.hpp>

namespace asymsecurefile
{

    namespace internal {

        namespace jasf3 {

			class InputStreamDelegateImpl::DataChunkQueueItem {
			private:
				std::vector<unsigned char> buffer_;
				int read_pos_;
				int size_;
			
			public:
				DataChunkQueueItem(const unsigned char* buffer, int size) : read_pos_(0) {
					size_ = size;
					buffer_.insert(buffer_.end(), buffer, &buffer[size]);
				}

                DataChunkQueueItem(const jcp::Buffer &buffer) : read_pos_(0){
					size_ = buffer.size();
					buffer_.insert(buffer_.end(), buffer.data(), &buffer.data()[buffer.size()]);
				}

				unsigned char *buffer() {
					return &buffer_[0];
				}

				int readPosition() const {
					return read_pos_;
				}

				int readRemaining() const {
					return size_ - read_pos_;
				}

				void incReadPosition(int size) {
					read_pos_ += size;
				}

				int size() const {
					return size_;
				}
			};

            template<class T>
            const T* InputStreamDelegateImpl::getSpecialChunk() const
            {
                auto found_iter = raw_chunk_map_.find(T::CHUNK_TYPE);
                if (found_iter != raw_chunk_map_.end())
                {
                    return dynamic_cast<const T*>(found_iter->second.get());
                }
                return NULL;
            }

			InputStreamDelegateImpl::InputStreamDelegateImpl(std::istream* is)
				: state_(State::STATE_READ_HEADER), footer_validated_(false), basic_inited_(false), read_prepared_(false), is_(is), default_header_chunk_(NULL), cached_user_chunks_(false)
			{
				auth_tag_.resize(16);
			}

			InputStreamDelegateImpl::~InputStreamDelegateImpl()
			{
			}

            Result<void> InputStreamDelegateImpl::setAuthKey(const unsigned char *auth_key, size_t length) {
                Result<int> result;

                auth_key_.clear();
                auth_key_.insert(auth_key_.end(), &auth_key[0], &auth_key[length]);

                if(!basic_inited_ && (!auth_key_.empty()) && (state_ != STATE_READ_HEADER)) {
                    std::unique_ptr<std::exception> e;
                    if (e = initBasic())
                        return ResultBuilder<void,  std::exception>().withOtherException(e).build();
                }
				return ResultBuilder<void, void>().build();
			}

            Result<int> InputStreamDelegateImpl::headerRead()
			{
				if (!fingerprint_digest_.get()) {
					fingerprint_digest_ = jcp::MessageDigest::getInstance(jcp::MessageDigestAlgorithm::SHA_256.algo_id());
				}
                return readPayload(STATE_READ_HEADER, false);
			}

            std::unique_ptr<std::exception> InputStreamDelegateImpl::initBasic() {
				default_header_chunk_ = getSpecialChunk<DefaultHeaderChunk>();
                if (!default_header_chunk_)
                {
                    return std::unique_ptr<std::exception>(new InvalidFileException("Chunk DefaultHeader empty"));
                }

                std::unique_ptr<jcp::Mac> auth_enc_key_mac = jcp::Mac::getInstance(jcp::MacAlgorithm::HmacSHA256.algo_id());
                jcp::SecretKey secretKey(this->auth_key_.data(), this->auth_key_.size());
                auth_enc_key_mac->init(&secretKey);
                {
                    const std::vector<unsigned char> &seed = default_header_chunk_->seed();
                    auth_enc_key_mac->update(seed.data(), seed.size());
                }
                auth_enc_key_.resize(auth_enc_key_mac->digest_size());
                jcp::Result<void> block_result = auth_enc_key_mac->digest(&auth_enc_key_[0]);
                if(!block_result) {
                    auth_enc_key_.clear();
                    return block_result.move_exception();
                }

                return NULL;
            }

            Result<int> InputStreamDelegateImpl::readPayload(State run_state, bool blocking)
			{
				int rc = 1;
				Result<int> temp_result;
				std::unique_ptr< std::exception > temp_exception;

				if (run_state == STATE_READ_DATA) {
					if (!read_prepared_) {
						if (!prepareReadData(temp_result)) {
							return temp_result;
						}
					}

					while (!cipher_data_queue_.empty()) {
						std::unique_ptr<DataChunkQueueItem> item(std::move(cipher_data_queue_.front())); cipher_data_queue_.pop_front();
						jcp::Result<jcp::Buffer> work_res = data_cipher_->update(item->buffer(), item->size());
						if (!work_res) {
							return ResultBuilder<int, std::exception>(0).withOtherException(work_res.move_exception()).build();
						}
						plain_data_queue_.push_back(std::unique_ptr<DataChunkQueueItem>(new DataChunkQueueItem(work_res->data(), work_res->size())));
					}
				}
				
				while (((is_->rdbuf()->in_avail() > 0) || blocking) && (rc == 1)) {
					int ret;
					if ((ret = reading_chunk_.read(temp_result, is_, blocking, fingerprint_digest_.get())) == 1) {
						switch (state_) {
						case STATE_READ_HEADER:
							if (reading_chunk_.getPrimaryType() != Jasf3ChunkType::DATA_STREAM) {
								int code = reading_chunk_.getPrimaryType() & 0xFF;
								if ((code & 0x80) != 0) {
									code = 0x800000 | reading_chunk_.getUserCode();
								}
                                raw_chunk_map_.emplace(code, Jasf3ChunkResolver::parseChunk(reading_chunk_.getPrimaryType(), 0, reading_chunk_.getSize(), reading_chunk_.getData()));
								break;
							}
							state_ = STATE_READ_DATA;
							rc = 0;
							if (!read_prepared_ && (asym_key_) && (!auth_key_.empty())) {
                                if(!prepareReadData(temp_result)) {
                                    return temp_result;
                                }
                            }
							if (!read_prepared_) {
                                cipher_data_queue_.push_back(std::unique_ptr<DataChunkQueueItem>(new DataChunkQueueItem(reading_chunk_.getData(), reading_chunk_.getSize())));
								break;
							}
							// Continue process to READ_DATA
						case STATE_READ_DATA:
							if (reading_chunk_.getPrimaryType() == Jasf3ChunkType::DATA_STREAM) {
                                jcp::Result<jcp::Buffer> result_with_buf = data_cipher_->update(reading_chunk_.getData(), reading_chunk_.getSize());
								plain_data_queue_.push_back(std::unique_ptr<DataChunkQueueItem>(new DataChunkQueueItem(*result_with_buf)));
								break;
							}
						case STATE_READ_FOOTER:
							raw_chunk_map_.emplace(reading_chunk_.getPrimaryType() & 0xff, Jasf3ChunkResolver::parseChunk(reading_chunk_.getPrimaryType(), (short)0, reading_chunk_.getSize(), reading_chunk_.getData()));
							state_ = STATE_READ_DONE;
							temp_exception = validateFooter();
							if (temp_exception) {
								return ResultBuilder<int, std::exception>(-1).withOtherException(temp_exception).build();
							}
							break;
						}
						reading_chunk_.reset();
						if (state_ == STATE_READ_DATA)
							break;
					}
					if (ret < 0)
						return ResultBuilder<int, void>(ret).build();
				}

				return ResultBuilder<int, void>(rc).build();
			}

            Result<void> InputStreamDelegateImpl::verifySignData(const std::vector<unsigned char>& signdata, const jcp::Buffer &fingerprint) {
                std::unique_ptr<jcp::Signature> signature = jcp::Signature::getInstance(algorithm_info_.getAlgorithmPtr()->getSignatureAlgorithm().c_str());
                signature->initVerify(this->asym_key_);
                signature->update(fingerprint.data(), fingerprint.size());
                jcp::Result<bool> result = signature->verify(signdata.data(), signdata.size());
                if(!result) {
                    return ResultBuilder<void, std::exception>().withOtherException(result.move_exception()).build();
                }
                if(!(*result)) {
                    return ResultBuilder<void, ValidateFailedException>().withException("Integrity validation failed").build();
                }
                return ResultBuilder<void, void>().build();
			}

			std::unique_ptr< std::exception > InputStreamDelegateImpl::validateFooter() {
				if (footer_validated_)
					return NULL;

				{
					jcp::Result<jcp::Buffer> result = data_cipher_->doFinal();
					if (!result) {
						return std::unique_ptr<ValidateFailedException>(new ValidateFailedException());
					}

					if (result->size()) {
						plain_data_queue_.push_back(std::unique_ptr<DataChunkQueueItem>(new DataChunkQueueItem(*result)));
					}
				}
                {
                    jcp::Result<jcp::Buffer> fingerprint_result = fingerprint_digest_->digest();
                    const FooterChunk *footer_chunk = getSpecialChunk<FooterChunk>();
                    if (memcmp(footer_chunk->fingerprint().data(), fingerprint_result->data(), fingerprint_result->size())) {
						return std::unique_ptr<ValidateFailedException>(new ValidateFailedException());
                    }

                    if (*default_header_chunk_->operation_type() == OperationType::SIGN) {
                        Result<void> verify_result = verifySignData(footer_chunk->signature(), *fingerprint_result);
                        if (!verify_result)
                            return verify_result.move_exception();
                    } else {
                        std::unique_ptr<jcp::Mac> mac = jcp::Mac::getInstance(jcp::MacAlgorithm::HmacSHA256.algo_id());
                        jcp::SecretKey secretKey(mac_key_.data(), mac_key_.size());
                        mac->init(&secretKey);
                        mac->update(fingerprint_result->data(), fingerprint_result->size());
                        jcp::Result<jcp::Buffer> mac_result = mac->digest();
                        if (!memcmp(footer_chunk->mac().data(), mac_result->data(), mac_result->size())) {
                            return std::unique_ptr<ValidateFailedException>(new ValidateFailedException());
                        }
                    }
                }

				footer_validated_ = true;
				return NULL;
            }

			bool InputStreamDelegateImpl::prepareReadData(Result<int>& result) {
				std::vector<unsigned char> data_key;

				if (auth_key_.empty()) {
					result = Result<int>(ResultBuilder<int, IOException>(-1).withException("Empty authKey").build());
					return false;
				}

				const DefaultHeaderChunk* defaultHeader = getSpecialChunk<DefaultHeaderChunk>();
				const AsymAlgorithmChunk* asymAlgorithmChunk = getSpecialChunk<AsymAlgorithmChunk>();
				const DataAlgorithmChunk* dataAlgorithmChunk = getSpecialChunk<DataAlgorithmChunk>();
				const DataIvChunk* dataIVChunk = getSpecialChunk<DataIvChunk>();

				algorithm_info_ = asymAlgorithmChunk->getAlgorithmInfo();

				if (!asym_key_) {
					result = Result<int>(ResultBuilder<int, IOException>(-1).withException("Empty authKey").build());
					return false;
				}

				if ((!defaultHeader) || (!asymAlgorithmChunk) || (!dataAlgorithmChunk) || (!dataIVChunk)) {
					result = Result<int>(ResultBuilder<int, IOException>(-1).withException("Empty Required chunk").build());
					return false;
				}

				// ========== Get SeedKey and DataKey & Store to chunk ==========

				if (*default_header_chunk_->operation_type() == OperationType::PUBLIC_ENCRYPT) {
					const EncryptedSeedKeyChunk* encryptedSeedKeyChunk = getSpecialChunk<EncryptedSeedKeyChunk>();
					const SeedKeyCheckChunk* seedKeyCheckChunk = getSpecialChunk<SeedKeyCheckChunk>();

					if ((!encryptedSeedKeyChunk) || (!seedKeyCheckChunk)) {
						result = Result<int>(ResultBuilder<int, IOException>(-1).withException("Empty Required chunk").build());
						return false;
					}

					std::vector<unsigned char> seed_key;
					std::unique_ptr<jcp::Mac> dataKeyMac = jcp::Mac::getInstance("HmacSHA512");
					jcp::SecretKey dataKeyMacSecretKey(auth_key_.data(), auth_key_.size());
					dataKeyMac->init(&dataKeyMacSecretKey);

					if (((*algorithm_info_.getAlgorithmPtr()) == AsymAlgorithm::EC) || ((*algorithm_info_.getAlgorithmPtr()) == AsymAlgorithm::PRIME)) {
						std::unique_ptr<jcp::KeyAgreement> key_agreement = jcp::KeyAgreement::getInstance(jcp::KeyAgreementAlgorithm::ECDH.algo_id());
						jcp::Result<std::unique_ptr<jcp::X509EncodedKeySpec>> public_key_spec = jcp::X509EncodedKeySpec::decode(encryptedSeedKeyChunk->getData(), encryptedSeedKeyChunk->getDataSize());
                        if(!public_key_spec) {
                            result = ResultBuilder<int, std::exception>(-1).withOtherException(public_key_spec.move_exception()).build();
                            return false;
                        }
                        std::unique_ptr<jcp::KeyFactory> public_key_factory = jcp::KeyFactory::getInstance("X509");
                        jcp::Result<std::unique_ptr<jcp::AsymKey>> localKey = public_key_factory->generatePublicKey(public_key_spec->get());
                        if(!localKey) {
                            result = ResultBuilder<int, std::exception>(-1).withOtherException(localKey.move_exception()).build();
                            return false;
                        }
						key_agreement->init(this->asym_key_);
						jcp::Result<jcp::SecretKey> dophase_result = key_agreement->doPhase(localKey->get());
						if (!dophase_result) {
							result = ResultBuilder<int, std::exception>(-1).withOtherException(dophase_result.move_exception()).build();
							return false;
						}
						jcp::Result<jcp::Buffer> ka_result = key_agreement->generateSecret();
						if (ka_result.exception()) {
							result = Result<int>(ResultBuilder<int, std::exception>(-1).withOtherException(ka_result.move_exception()).build());
							return false;
						}
						seed_key.insert(seed_key.end(), ka_result->data(), ka_result->data() + ka_result->size());
					}
					else if (((*algorithm_info_.getAlgorithmPtr()) == AsymAlgorithm::RSA)) {
						std::unique_ptr<jcp::Cipher> seedKeyCipher = jcp::Cipher::getInstance(jcp::CipherAlgorithm::RsaEcbOaepPadding.algo_id());
						seedKeyCipher->init(jcp::Cipher::DECRYPT_MODE, this->asym_key_);
						jcp::Result<jcp::Buffer> seed_key_result = seedKeyCipher->doFinal(encryptedSeedKeyChunk->getData(), encryptedSeedKeyChunk->getDataSize());
						if (seed_key_result.exception()) {
							result = Result<int>(ResultBuilder<int, std::exception>(-1).withOtherException(seed_key_result.move_exception()).build());
							return false;
						}
						seed_key.insert(seed_key.end(), seed_key_result->data(), seed_key_result->data() + seed_key_result->size());
					}
					else {
						return false;
					}

					dataKeyMac->update(seed_key.data(), seed_key.size());
					jcp::Result<jcp::Buffer> bigkey_result = dataKeyMac->digest();
					data_key.insert(data_key.end(), bigkey_result->data(), bigkey_result->data() + 32);
					mac_key_.insert(mac_key_.end(), bigkey_result->data() + 32, bigkey_result->data() + 64);

					if (!seedKeyCheckChunk->verify(seed_key)) {
						result = Result<int>(ResultBuilder<int, ValidateFailedException>(-1).withException("Different Key").build());
						return false;
					}

					int dataKeySize = dataAlgorithmChunk->dataAlgorithmPtr()->getKeySize();
					if (dataKeySize > data_key.size()) {
						data_key.resize(dataKeySize);
					}
					else if( dataKeySize < data_key.size()) {
						// throw new RuntimeException("Not support key size = " + (dataKeySize * 8));
					}
				}
				else {
					data_key = auth_enc_key_;
					mac_key_ = auth_key_;
				}

				data_cipher_ = createDataCipher(dataAlgorithmChunk->dataAlgorithmPtr(), dataIVChunk->iv(), data_key, mac_key_);

				read_prepared_ = true;

				return true;
			}

            std::unique_ptr< std::exception > InputStreamDelegateImpl::parseUserChunks() {
                if(cached_user_chunks_)
                    return NULL;

                for(auto iter = raw_chunk_map_.cbegin(); iter != raw_chunk_map_.cend(); iter++) {
                    if(iter->first & 0x800000) {
						const RawUserChunk* rawUserChunk = (const RawUserChunk*)iter->second.get();
                        if(rawUserChunk->getFlag() && (*rawUserChunk->getFlag() == Chunk::Flag::EncryptedWithAuthEncKey)) {
							std::vector<unsigned char> dataIV(16);
							memcpy(&dataIV[0], rawUserChunk->getData(), dataIV.size());
							std::unique_ptr<jcp::Cipher> cipher = createChunkCipher(dataIV, auth_enc_key_, auth_key_);
							jcp::Result<jcp::Buffer> plaintext = cipher->doFinal(rawUserChunk->getData() + 16, rawUserChunk->getDataSize() - 16);
							if (plaintext.exception()) {
								if(dynamic_cast<const jcp::exception::AEADBadTagException*>(plaintext.exception())) {
                                    return std::unique_ptr<ValidateFailedException>(new ValidateFailedException("UserChunk integrity validation failed"));
                                }
								return plaintext.move_exception();
							}
                            cached_user_chunk_map_[iter->first & 0xFFFF] = std::unique_ptr<RawUserChunk>(new RawUserChunk(rawUserChunk->getPrimaryType(), rawUserChunk->getUserCode(), (short)plaintext->size(), plaintext->data()));
                        }else{
                            cached_user_chunk_map_[iter->first & 0xFFFF] = std::unique_ptr<RawUserChunk>(new RawUserChunk(rawUserChunk));
                        }
                    }
                }
            }

            void InputStreamDelegateImpl::setAsymKey(const jcp::AsymKey *key) {
                asym_key_ = key;
            }

            Result<int> InputStreamDelegateImpl::available() {
                return Result<int>();
            }

            Result<int> InputStreamDelegateImpl::read(unsigned char *buffer, size_t size) {
                int readSize = 0;
                Result<int> readResult;
                if(state_ != STATE_READ_DATA) {
                    readResult = readPayload(STATE_READ_HEADER, false);
                }else {
                    readResult = readPayload(STATE_READ_DATA, false);
					if (readResult.exception()) {
						return readResult;
					}
                    if ((*readResult) == 0) {
                        // If data read has done
						readResult = readPayload(STATE_READ_FOOTER, true);
						if (readResult.exception()) {
							return readResult;
						}
                    }
                }
                {
                    if(!plain_data_queue_.empty()) {
						std::unique_ptr<DataChunkQueueItem> dataChunkQueueItem(std::move(plain_data_queue_.front())); plain_data_queue_.pop_front();
                        readSize = (size < dataChunkQueueItem->readRemaining()) ? size : dataChunkQueueItem->readRemaining();
                        memcpy(buffer, dataChunkQueueItem->buffer() + dataChunkQueueItem->readPosition(), readSize);
                        dataChunkQueueItem->incReadPosition(readSize);
                        if(dataChunkQueueItem->readRemaining() > 0) {
                            plain_data_queue_.push_front(std::move(dataChunkQueueItem)); // Re-insert
                        }
                    }else{
                        if(state_ == STATE_READ_DONE)
                            return ResultBuilder<int, void>(-1).build();
                    }
                }
                return ResultBuilder<int, void>(readSize).build();
            }

            Result<const UserChunk *> InputStreamDelegateImpl::getUserChunk(uint16_t code) {
				std::unique_ptr< std::exception > e(parseUserChunks());
                if(e)
                    return ResultBuilder<const UserChunk *,  std::exception>().withOtherException(e).build();
                const auto iter = cached_user_chunk_map_.find(code);
                if(iter != cached_user_chunk_map_.cend()) {
                    return ResultBuilder<const UserChunk *, void>(iter->second.get()).build();
                }
                return Result<const UserChunk *>(ResultBuilder<const UserChunk *, void>(nullptr).build());
            }

            Result<std::vector<const UserChunk *>> InputStreamDelegateImpl::userChunks() {
                std::unique_ptr< std::exception > e(parseUserChunks());
                if(e)
                    return ResultBuilder< std::vector<const UserChunk *>,  std::exception>().withOtherException(e).build();
                std::unique_ptr<ResultImpl<std::vector<const UserChunk *>, void>> result_impl(new ResultImpl<std::vector<const UserChunk *>, void>());
                result_impl->result().reserve(cached_user_chunk_map_.size());
				for(auto iter = cached_user_chunk_map_.cbegin(); iter != cached_user_chunk_map_.cend(); iter++) {
                    result_impl->result().push_back(iter->second.get());
                }
                return Result< std::vector<const UserChunk *> >(std::move(result_impl));
            }

            bool InputStreamDelegateImpl::isDataReadable() {
                return false;
            }

            bool InputStreamDelegateImpl::validate() {
                return false;
            }



            std::unique_ptr<jcp::Cipher> InputStreamDelegateImpl::createDataCipher(const DataAlgorithm *dataAlgorithm, const std::vector<unsigned char>& dataIV, const std::vector<unsigned char>& key, const std::vector<unsigned char>& authKey) {
                std::unique_ptr<jcp::Cipher> cipher = jcp::Cipher::getInstance(dataAlgorithm->getAlgorithm().c_str());
                jcp::SecretKey secretKey(key.data(), key.size());

                if(dataAlgorithm->isContainMac()) {
                    cipher->init(jcp::Cipher::DECRYPT_MODE, &secretKey, jcp::GCMParameterSpec::create(128, dataIV.data(), dataIV.size()).get());
                    cipher->updateAAD(authKey.data(), authKey.size());
                }else{
                    cipher->init(jcp::Cipher::DECRYPT_MODE, &secretKey, jcp::IvParameterSpec::create(dataIV.data(), dataIV.size()).get());
                }
                return cipher;
            }

            std::unique_ptr<jcp::Cipher> InputStreamDelegateImpl::createChunkCipher(const std::vector<unsigned char>& dataIV, const std::vector<unsigned char>& key, const std::vector<unsigned char>& authKey) {
                std::unique_ptr<jcp::Cipher> cipher = jcp::Cipher::getInstance("AES/GCM/NoPadding");
                jcp::SecretKey secretKey(key.data(), key.size());
                cipher->init(jcp::Cipher::DECRYPT_MODE, &secretKey, jcp::GCMParameterSpec::create(128, dataIV.data(), dataIV.size()).get());
                cipher->updateAAD(authKey.data(), authKey.size());
                return cipher;
            }

        } // namesppace jasf3

    } // namespace internal

} // namespace asymsecurefile
