/**
 * @file	input_stream_delegate_impl.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "ssf_input_stream_delegate.hpp"

namespace asymsecurefile {

    namespace internal {

        namespace ssf {

			int InputStreamDelegateImpl::headerRead(Result<int>& result)
			{
				return false;
			}

        } // namesppace ssf

    } // namespace internal

} // namespace asymsecurefile

