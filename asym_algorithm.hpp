/**
 * @file	asym_algorithm.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <vector>
#include <string>

namespace asymsecurefile
{
	class AsymAlgorithm
	{
	public:
		static AsymAlgorithm Unknown;
		static AsymAlgorithm EC;
		static AsymAlgorithm PRIME;
		static AsymAlgorithm RSA;

	private:
		static std::vector<const AsymAlgorithm*> values_;

		class StaticInitializer
		{
		public:
			StaticInitializer();
		};

		static StaticInitializer si_;

	private:
		const unsigned char key_type_;
		const std::string name_;
		const std::vector<unsigned char> identifier_;
		const std::string algorithm_;
		const std::string signature_algorithm_;
	public:
		AsymAlgorithm(unsigned char key_type);
		AsymAlgorithm(unsigned char key_type, const std::string& name, const std::vector<unsigned char>& identifier, const std::string& algorithm, const std::string& signatureAlgorithm);

		int getKeyType() const;

		std::vector<unsigned char> getIdentifier() const;

		std::string getAlgorithm() const;

		std::string getSignatureAlgorithm() const;

	public:
		bool operator == (const AsymAlgorithm& other) const;
		bool operator != (const AsymAlgorithm& other) const;
		static std::vector<const AsymAlgorithm*> values();
		std::string toString() const;
	}; // class AsymAlgorithm

} // namespace asymsecurefile
