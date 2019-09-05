/**
 * @file	memstream.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <streambuf>
#include <istream>
#include <memory>

struct membuf : std::streambuf {
	membuf(char const* base, size_t size) {
		char* p(const_cast<char*>(base));
		this->setg(p, p, p + size);
	}
};
struct imemstream : virtual membuf, std::istream {
	imemstream(char const* base, size_t size)
		: membuf(base, size)
		, std::istream(static_cast<std::streambuf*>(this)) {
	}
};

namespace asymsecurefile {

	struct membuf : std::streambuf {
		membuf() { }
		membuf(const char * base, size_t size) {
			char* p(const_cast<char*>(base));
			this->setg(p, p, p + size);
		}
		void setmembuf(const char * base, size_t size) {
			char* p(const_cast<char*>(base));
			this->setg(p, p, p + size);
		}
	};

	template<typename TStore>
	struct imemstream;

	template<>
	struct imemstream<const char*> : virtual membuf, std::istream {
		imemstream(const char* base, size_t size)
			: membuf(base, size)
			, std::istream(static_cast<std::streambuf*>(this)) {
		}
	};

	template<>
	struct imemstream< std::unique_ptr<const char> > : virtual membuf, std::istream {
		std::unique_ptr<const char> store_;
		imemstream(std::unique_ptr<const char> base, size_t size)
			: store_(std::move(base))
			, membuf()
			, std::istream(static_cast<std::streambuf*>(this)) {
			setmembuf(store_.get(), size);
		}
	};

} // namespace src

