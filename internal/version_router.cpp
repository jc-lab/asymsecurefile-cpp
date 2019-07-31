/**
 * @file	version_router.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "version_router.hpp"

#include <memory>
#include "input_stream_delegate.hpp"
#include "output_stream_delegate.hpp"
#include "jasf3/jasf3_input_stream_delegate.hpp"
#include "jasf3/jasf3_output_stream_delegate.hpp"
#include "signedsecurefile/ssf_input_stream_delegate.hpp"

namespace asymsecurefile
{
    namespace internal {

        std::map<uint8_t, std::unique_ptr<VersionRouter::InputStreamDelegateFactory> > VersionRouter::reader_map_;
        std::map<uint8_t, std::unique_ptr<VersionRouter::OutputStreamDelegateFactory> > VersionRouter::writer_map_;

        VersionRouter::StaticInitializer VersionRouter::si_;

        class Jasf3InputStreamDelegateFactory : public VersionRouter::InputStreamDelegateFactory {
        public:
            std::unique_ptr<InputStreamDelegate> create(std::istream* is) const override {
                return std::unique_ptr<InputStreamDelegate>(new jasf3::InputStreamDelegateImpl(is));
            }
        };

        class Jasf3OutputStreamDelegateFactory : public VersionRouter::OutputStreamDelegateFactory {
        public:
            std::unique_ptr<OutputStreamDelegate> create() const override {
                return std::unique_ptr<OutputStreamDelegate>(new jasf3::OutputStreamDelegateImpl());
            }
        };

        class SsfInputStreamDelegateFactory : public VersionRouter::InputStreamDelegateFactory {
        public:
            std::unique_ptr<InputStreamDelegate> create(std::istream *is) const override {
				return NULL;
                //return std::unique_ptr<InputStreamDelegate>(new ssf::InputStreamDelegateImpl());
            }
        };

        VersionRouter::StaticInitializer::StaticInitializer() {
            reader_map_[1].reset(new SsfInputStreamDelegateFactory());
            reader_map_[2].reset(new SsfInputStreamDelegateFactory());
            reader_map_[3].reset(new Jasf3InputStreamDelegateFactory());
            writer_map_[3].reset(new Jasf3OutputStreamDelegateFactory());
        }

        VersionRouter::InputStreamDelegateFactory* VersionRouter::findReaderDelegate(uint8_t version) {
            std::map<uint8_t, std::unique_ptr<InputStreamDelegateFactory> >::const_iterator iter = reader_map_.find(version);
            if(iter != reader_map_.cend()) {
                return iter->second.get();
            }
            return NULL;
        }

        VersionRouter::OutputStreamDelegateFactory* VersionRouter::findWriterDelegate(uint8_t version) {
            std::map<uint8_t, std::unique_ptr<OutputStreamDelegateFactory> >::const_iterator iter = writer_map_.find(version);
            if(iter != writer_map_.cend()) {
                return iter->second.get();
            }
            return NULL;
        }

    }
}
