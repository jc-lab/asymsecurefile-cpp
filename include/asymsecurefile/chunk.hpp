/**
 * @file	chunk.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <vector>
#include <string>
#include <stdint.h>

namespace asymsecurefile
{
	class Chunk
	{
	public:
		class Flag {
		public:
			static Flag None;
			static Flag EncryptedWithCustomKey;
			static Flag SignedSignature;
			static Flag EncryptedWithAuthEncKey;

		private:
			static std::vector<const Flag*> values_;

			class StaticInitializer
			{
			public:
				StaticInitializer();
			};

			static StaticInitializer si_;

		private:
			uint8_t value_;
			std::string name_;

		public:
			Flag(unsigned char value, const std::string& name);

			uint8_t getValue() const;

		public:
			bool operator == (const Flag& other) const;
			bool operator != (const Flag& other) const;
			static std::vector<const Chunk::Flag*> values();
			std::string toString() const;
			static const Flag* valueOf(uint8_t value);
		};

	protected:
		uint8_t primary_type_;
		uint16_t user_code_;
		uint16_t data_size_;
		std::vector<uint8_t> data_;

	public:
		Chunk(uint8_t primary_type, uint16_t user_code, uint16_t data_size, const uint8_t* data);
		Chunk(uint8_t primary_type, const std::vector<uint8_t>& data);
		virtual ~Chunk() {}
		const Flag* getFlag() const;
		uint32_t getChunkId() const;
		uint8_t getPrimaryType() const;
		uint16_t getDataSize() const;
		const uint8_t* getData() const;
		const std::vector<uint8_t>& getDataVector() const;

	}; // class Chunks

} // namespace src
