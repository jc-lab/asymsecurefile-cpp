/**
 * @file	data_algorithm.hpp
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
	class DataAlgorithm
	{
	public:
		static DataAlgorithm Unknown;
		static DataAlgorithm AES256_GCM;

	private:
		static std::vector<const DataAlgorithm*> values_;

		class StaticInitializer
		{
		public:
			StaticInitializer();
		};

		static StaticInitializer si_;

	private:
		const std::string name_;
		const std::vector<unsigned char> identifier_;
		const std::string algo_name_;
		const int key_size_;
		const bool contain_mac_;
	public:
		DataAlgorithm(const std::string& name);
		DataAlgorithm(const std::string& name, const std::vector<unsigned char>& identifier, const char* algo_name, int key_size, bool contain_mac);

        const std::vector<unsigned char>& getIdentifier() const;

		const std::string& getAlgorithm() const;

		int getKeySize() const;

		bool isContainMac() const;

	public:
		bool operator == (const DataAlgorithm& other) const;
		bool operator != (const DataAlgorithm& other) const;
		static std::vector<const DataAlgorithm*> values();
		std::string toString() const;
	}; // class DataAlgorithm

} // namespace asymsecurefile
