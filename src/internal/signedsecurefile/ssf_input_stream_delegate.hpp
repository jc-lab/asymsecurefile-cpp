/**
 * @file	input_stream_delegate_impl.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "asymsecurefile/internal/input_stream_delegate.hpp"

namespace asymsecurefile {

    namespace internal {

        namespace ssf {

            class InputStreamDelegateImpl : public InputStreamDelegate
            {
			public:
				bool headerRead(Result<int>& result);
            };

        } // namesppace ssf

    } // namespace internal

} // namespace src
