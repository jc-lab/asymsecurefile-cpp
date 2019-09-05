/**
 * @file	chunk.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <asymsecurefile/chunk.hpp>

namespace asymsecurefile
{
	Chunk::Flag Chunk::Flag::None(0x00, "None");
	Chunk::Flag Chunk::Flag::EncryptedWithCustomKey(0x01, "EncryptedWithCustomKey");
	Chunk::Flag Chunk::Flag::SignedSignature(0x02, "SignedSignature");
	Chunk::Flag Chunk::Flag::EncryptedWithAuthEncKey(0x03, "EncryptedWithAuthEncKey");

	std::vector<const Chunk::Flag*> Chunk::Flag::values_;
	Chunk::Flag::StaticInitializer Chunk::Flag::si_;

	Chunk::Flag::StaticInitializer::StaticInitializer()
	{
		values_.push_back(&EncryptedWithCustomKey);
		values_.push_back(&SignedSignature);
		values_.push_back(&EncryptedWithAuthEncKey);
	}

	Chunk::Flag::Flag(unsigned char value, const std::string& name)
		: value_(value), name_(name)
	{
	}

	uint8_t Chunk::Flag::getValue() const
	{
		return value_;
	}

	bool Chunk::Flag::operator == (const Chunk::Flag& other) const
	{
		return this->value_ == other.value_;
	}

	bool Chunk::Flag::operator != (const Chunk::Flag& other) const
	{
		return this->value_ != other.value_;
	}

	std::vector<const Chunk::Flag*> Chunk::Flag::values()
	{
		return values_;
	}

	std::string Chunk::Flag::toString() const
	{
		return name_;
	}

	const Chunk::Flag* Chunk::Flag::valueOf(uint8_t value)
	{
		for (std::vector<const Flag*>::const_iterator iter = values_.begin(); iter != values_.end(); iter++)
		{
			if ((*iter)->value_ == value)
			{
				return *iter;
			}
		}
		return &None;
	}


	Chunk::Chunk(uint8_t primary_type, uint16_t user_code, uint16_t data_size, const uint8_t* data)
		: primary_type_(primary_type), user_code_(user_code), data_size_(data_size)
	{
		if (data_size > 0) {
			data_.insert(data_.end(), &data[0], &data[data_size]);
		}
	}

	Chunk::Chunk(uint8_t primary_type, const std::vector<uint8_t>& data)
		: primary_type_(primary_type), user_code_(0), data_size_(data.size()), data_(data)
	{
	}

	const Chunk::Flag* Chunk::getFlag() const
	{
		if ((primary_type_ & 0x80) != 0) {
			uint8_t value = (primary_type_ & 0x7F);
			return Flag::valueOf(value);
		}
		return NULL;
	}

	uint32_t Chunk::getChunkId() const
	{
		if ((primary_type_ & 0x80) != 0) {
			return 0x800000 | (user_code_ & 0xFFFF);
		}
		return primary_type_;
	}

	uint8_t Chunk::getPrimaryType() const
	{
		return primary_type_;
	}

	uint16_t Chunk::getDataSize() const
	{
		return data_size_;
	}

	const uint8_t* Chunk::getData() const
	{
		return data_.data();
	}

	const std::vector<uint8_t> &Chunk::getDataVector() const
	{
		return data_;
	}
}
