/**
 * @file	invalid_file_exception.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <exception>

namespace asymsecurefile {

	class InvalidFileException : public std::exception {
	public:
        InvalidFileException()
                : exception("Invalid file")
        {
        }

        explicit InvalidFileException(char const *const _Message) : exception(_Message) {

        }

        InvalidFileException(char const *const _Message, int i) : exception(_Message, i) {

        }

        virtual ~InvalidFileException() {}
    };

} // namespace src

