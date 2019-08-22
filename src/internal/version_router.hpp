/**
 * @file	version_router.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <map>
#include <memory>
#include <stdint.h>

namespace asymsecurefile
{
    namespace internal {
        class InputStreamDelegate;

        class OutputStreamDelegate;

        class VersionRouter {
        public:
            class InputStreamDelegateFactory {
            public:
                virtual std::unique_ptr<InputStreamDelegate> create(std::istream* is) const = 0;
            };

            class OutputStreamDelegateFactory {
            public:
                virtual std::unique_ptr<OutputStreamDelegate> create() const = 0;
            };

        public:
            class StaticInitializer {
            public:
                StaticInitializer();
            };

            static std::map<uint8_t, std::unique_ptr<InputStreamDelegateFactory> > reader_map_;
            static std::map<uint8_t, std::unique_ptr<OutputStreamDelegateFactory> > writer_map_;

            static StaticInitializer si_;

            static InputStreamDelegateFactory* findReaderDelegate(uint8_t version);
            static OutputStreamDelegateFactory* findWriterDelegate(uint8_t version);

        }; // class SignatureHeader

    }; // namespace internal

} // namespace src
