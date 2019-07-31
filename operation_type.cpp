/**
 * @file	operation_type.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "operation_type.hpp"

namespace asymsecurefile
{
	OperationType OperationType::Unknown("Unknown", 0);
	OperationType OperationType::SIGN("SIGN", 1);
	OperationType OperationType::PUBLIC_ENCRYPT("PUBLIC_ENCRYPT", 2);

	std::vector<const OperationType*> OperationType::values_;
	OperationType::StaticInitializer OperationType::si_;

	OperationType::StaticInitializer::StaticInitializer()
	{
		values_.push_back(&SIGN);
		values_.push_back(&PUBLIC_ENCRYPT);
	}

	OperationType::OperationType()
		: value_(0)
	{
	}

	OperationType::OperationType(const std::string& name, uint8_t value)
		: name_(name), value_(value)
	{
	}

	uint8_t OperationType::value() const
	{
		return value_;
	}

	bool OperationType::operator == (const OperationType& other) const
	{
		return value_ == other.value_;
	}

	bool OperationType::operator != (const OperationType& other) const
	{
		return !(*this == other);
	}

	std::vector<const OperationType*> OperationType::values()
	{
		return values_;
	}

	std::string OperationType::toString() const
	{
		return name_;
	}

	const OperationType* OperationType::valueOf(uint8_t value)
	{
		for (std::vector<const OperationType*>::const_iterator iter = OperationType::values_.begin(); iter != OperationType::values_.end(); iter++)
		{
			if ((*iter)->value_ == value)
			{
				return *iter;
			}
		}
		return NULL;
	}
}
