/**
 * @file	data_algorithm.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <asymsecurefile/data_algorithm.hpp>

namespace asymsecurefile
{
	// AES256-GCM / 2.16.840.1.101.3.4.1.46
	DataAlgorithm DataAlgorithm::Unknown("Unknown");
	DataAlgorithm DataAlgorithm::AES256_GCM("AES256_GCM", std::vector<unsigned char> {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E}, "AES/GCM/NoPadding", 256, true);

	std::vector<const DataAlgorithm*> DataAlgorithm::values_;
	DataAlgorithm::StaticInitializer DataAlgorithm::si_;

	DataAlgorithm::StaticInitializer::StaticInitializer()
	{
		values_.push_back(&AES256_GCM);
	}

	DataAlgorithm::DataAlgorithm(const std::string& name)
		: name_(name), key_size_(0), contain_mac_(false)
	{
	}

	DataAlgorithm::DataAlgorithm(const std::string& name, const std::vector<unsigned char>& identifier, const char* algo_name, int key_size, bool contain_mac)
		: name_(name), identifier_(identifier), algo_name_(algo_name), key_size_(key_size), contain_mac_(contain_mac)
	{
	}

    const std::vector<unsigned char>& DataAlgorithm::getIdentifier() const
	{
		return identifier_;
	}

    const std::string& DataAlgorithm::getAlgorithm() const
    {
	    return algo_name_;
	}

	int DataAlgorithm::getKeySize() const
	{
		return key_size_;
	}

	bool DataAlgorithm::isContainMac() const
	{
		return contain_mac_;
	}

	bool DataAlgorithm::operator == (const DataAlgorithm& other) const
	{
		if (this->identifier_.size() != other.identifier_.size())
			return false;
		std::vector<unsigned char>::const_iterator it_1 = this->identifier_.begin();
		std::vector<unsigned char>::const_iterator it_2 = other.identifier_.begin();
		while (it_1 != this->identifier_.end())
		{
			if (*it_1 != *it_2)
				return false;
			it_1++;
			it_2++;
		}
		return true;
	}

	bool DataAlgorithm::operator != (const DataAlgorithm& other) const
	{
		return !(*this == other);
	}

	std::vector<const DataAlgorithm*> DataAlgorithm::values()
	{
		return values_;
	}

	std::string DataAlgorithm::toString() const
	{
		return name_;
	}
}
