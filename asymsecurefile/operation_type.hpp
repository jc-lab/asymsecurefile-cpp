/**
 * @file	operation_type.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <vector>

#include <string>

namespace asymsecurefile
{
	class OperationType
	{
	public:
		static OperationType Unknown;
		static OperationType SIGN;
		static OperationType PUBLIC_ENCRYPT;

	private:
		static std::vector<const OperationType*> values_;

		class StaticInitializer
		{
		public:
			StaticInitializer();
		};

		static StaticInitializer si_;

	private:
		const std::string name_;
		const uint8_t value_;
	public:
		OperationType();
		OperationType(const std::string& name, uint8_t value);

		uint8_t value() const;

	public:
		bool operator == (const OperationType& other) const;
		bool operator != (const OperationType& other) const;
		static std::vector<const OperationType*> values();
		std::string toString() const;
		static const OperationType* valueOf(uint8_t value);
	}; // class OperationType

} // namespace asymsecurefile
