/**
 * @file	asym_algorithm.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "asym_algorithm.hpp"

namespace asymsecurefile
{
	// EC // 1.3.132.0 // 06 04 2B 81 04 00
	// PRIME // 1.2.840.10045  // 06 07 2A 86 48 CE 3D 03 01
	// RSA Encryption // 1.2.840.113549.1.1 // 06 08 2A 86 48 86 F7 0D 01 01
	AsymAlgorithm AsymAlgorithm::EC(0x11, "EC", std::vector<unsigned char> {0x06, 0x04, 0x2B, 0x81, 0x04, 0x00}, "EC", "NONEwithECDSA");
	AsymAlgorithm AsymAlgorithm::PRIME(0x12, "PRIME", std::vector<unsigned char> {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01}, "EC", "NONEwithECDSA");
	AsymAlgorithm AsymAlgorithm::RSA(0x20, "RSA", std::vector<unsigned char> {0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01}, "EC", "NONEwithRSA");
	AsymAlgorithm AsymAlgorithm::Unknown(0);

	std::vector<const AsymAlgorithm*> AsymAlgorithm::values_;
	AsymAlgorithm::StaticInitializer AsymAlgorithm::si_;

	AsymAlgorithm::StaticInitializer::StaticInitializer()
	{
		values_.push_back(&EC);
		values_.push_back(&PRIME);
		values_.push_back(&RSA);
	}

	AsymAlgorithm::AsymAlgorithm(unsigned char key_type)
		: key_type_(key_type)
	{

	}

	AsymAlgorithm::AsymAlgorithm(unsigned char key_type, const std::string& name, const std::vector<unsigned char>& identifier, const std::string& algorithm, const std::string& signature_algorithm)
		: key_type_(key_type), name_(name), identifier_(identifier), algorithm_(algorithm), signature_algorithm_(signature_algorithm)
	{
	}

	int AsymAlgorithm::getKeyType() const
	{
		return key_type_;
	}

	std::vector<unsigned char> AsymAlgorithm::getIdentifier() const
	{
		return identifier_;
	}

	std::string AsymAlgorithm::getAlgorithm() const
	{
		return algorithm_;
	}

	std::string AsymAlgorithm::getSignatureAlgorithm() const
	{
		return signature_algorithm_;
	}

	bool AsymAlgorithm::operator == (const AsymAlgorithm& other) const
	{
		return this->key_type_ == other.key_type_;
	}

	bool AsymAlgorithm::operator != (const AsymAlgorithm& other) const
	{
		return this->key_type_ != other.key_type_;
	}

	std::vector<const AsymAlgorithm*> AsymAlgorithm::values()
	{
		return values_;
	}

	std::string AsymAlgorithm::toString() const
	{
		return name_;
	}
}
