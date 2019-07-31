/**
 * @file	result.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/17
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <memory>

namespace asymsecurefile {

    template<typename TResult, class TException>
    class ResultBuilder;

    template<typename TResult>
    class Result {
    protected:
        TResult result_;

    public:
        Result() {}

		Result(const TResult& value)
			: result_(value)
		{ }

        template<typename... Args>
        Result(Args&& ... eargs)
                : result_(eargs...)
        { }

        virtual ~Result() {}

        const TResult& result() const {
            return result_;
        }

        virtual const std::exception* exception() const = 0;
        virtual std::unique_ptr<std::exception> move_exception() = 0;
    };

	template <>
	class Result<void> {
	public:
		Result() {}

		bool result() const {
			return (exception() == NULL);
		}
		virtual const std::exception* exception() const = 0;
        virtual std::unique_ptr<std::exception> move_exception() = 0;
	};

	template<typename TResult, class TException>
	class ResultImpl : public Result<TResult> {
	protected:
		friend class ResultBuilder<TResult, TException>;
		std::unique_ptr<TException> e_;

	public:
		ResultImpl()
			: Result()
		{ }

		ResultImpl(const TResult& value)
			: Result(value)
		{ }

		template<typename... Args>
		ResultImpl(Args&& ... eargs)
			: Result(eargs...)
		{ }

		const std::exception* exception() const override {
			return e_.get();
		}

		std::unique_ptr<std::exception> move_exception() override {
			return std::move(e_);
		}
	};

	template<typename TResult>
	class ResultImpl<TResult, void> : public Result<TResult> {
	protected:
		friend class ResultBuilder<TResult, void>;

	public:
		ResultImpl()
			: Result()
		{ }

		ResultImpl(const TResult& value)
			: Result(value)
		{ }

		template<typename... Args>
		ResultImpl(Args&& ... eargs)
			: Result(eargs...)
		{ }

		const std::exception* exception() const override {
			return NULL;
		}

		std::unique_ptr<std::exception> move_exception() override {
			return NULL;
		}

		TResult &result() {
			return result_;
		}
	};

	template<class TException>
	class ResultImpl<void, TException> : public Result<void> {
	protected:
		friend class ResultBuilder<void, TException>;
		std::unique_ptr<TException> e_;

	public:
		ResultImpl()
			: Result()
		{ }

		const std::exception* exception() const override {
			return e_.get();
		}

		std::unique_ptr<std::exception> move_exception() override {
			return std::move(e_);
		}
	};

	template<>
	class ResultImpl<void, void> : public Result<void> {
	protected:
		friend class ResultBuilder<void, void>;

	public:
		ResultImpl()
			: Result()
		{ }

		const std::exception* exception() const override {
			return NULL;
		}

		std::unique_ptr<std::exception> move_exception() override {
			return NULL;
		}
	};

	template<typename TResult, class TException>
	class ResultBuilder {
	private:
        std::unique_ptr<ResultImpl<TResult, TException>> result_;

	public:
		ResultBuilder() : result_(new ResultImpl<TResult, TException>()) {
		}

        template<typename... RArgs>
        ResultBuilder(RArgs... args) : result_(new ResultImpl<TResult, TException>(args...)) {
        }

        ResultBuilder<TResult, TException>&withOtherException(std::unique_ptr<TException> &e) {
            result_->e_ = std::move(e);
            return *this;
        }

        template<typename... EArgs>
        ResultBuilder<TResult, TException>&withException(EArgs... args) {
			result_->e_ = std::unique_ptr<TException>(new TException(args...));
            return *this;
        }

        std::unique_ptr<ResultImpl<TResult, TException>> build() {
            return std::move(result_);
        }
	};

    template<class TException>
    class ResultBuilder<void, TException> {
    private:
        std::unique_ptr<ResultImpl<void, TException>> result_;

    public:
        ResultBuilder() : result_(new ResultImpl<void, TException>()) {
        }

        template<class TException>
        ResultBuilder<void, TException>&withOtherException(std::unique_ptr<TException> &e) {
            result_->e_ = std::move(e);
            return *this;
        }

        template<typename... EArgs>
        ResultBuilder<void, TException>&withException(EArgs... args) {
            result_->e_ = std::unique_ptr<TException>(new TException(args...));
            return *this;
        }

        std::unique_ptr<ResultImpl<void, TException>> build() {
            return std::move(result_);
        }
    };

    template<typename TResult>
    class ResultBuilder<TResult, void> {
    private:
        std::unique_ptr<ResultImpl<TResult, void>> result_;

    public:
		ResultBuilder(const TResult &value) : result_(new ResultImpl<TResult, void>(value)) {
		}

        template<typename... RArgs>
        ResultBuilder(RArgs... args) : result_(new ResultImpl<TResult, void>(args...)) {
        }

        std::unique_ptr<ResultImpl<TResult, void>> build() {
            return std::move(result_);
        }
    };

	template<>
	class ResultBuilder<void, void> {
	private:
		std::unique_ptr<ResultImpl<void, void>> result_;

	public:
		ResultBuilder() : result_(new ResultImpl<void, void>()) {
		}

		std::unique_ptr<ResultImpl<void, void>> build() {
			return std::move(result_);
		}
	};


} // namespace asymsecurefile

