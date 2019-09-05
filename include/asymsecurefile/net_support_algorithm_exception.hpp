/**
 * @file	not_support_version_exception.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <exception>

namespace asymsecurefile {

	class NotSupportAlgorithmException : std::exception {
	public:
		NotSupportAlgorithmException()
			: exception("Not support algorithm")
		{}
		virtual ~NotSupportAlgorithmException() {}
	};

} // namespace src

