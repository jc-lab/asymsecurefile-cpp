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
    class ResultData {
    protected:
        TResult result_;

    public:
        ResultData() {}

        template<typename... Args>
        ResultData(Args&& ... eargs)
                : result_(eargs...)
        { }

        virtual ~ResultData() {}

        const TResult& result() const {
            return result_;
        }

        virtual const std::exception* exception() const = 0;
        virtual std::unique_ptr<std::exception> move_exception() = 0;
    };

    template<typename TResult>
    class ResultData<std::unique_ptr<TResult>> {
    protected:
        std::unique_ptr<TResult> result_;

    public:
        ResultData() {}

        ResultData(std::unique_ptr<TResult> &obj)
            : result_(std::move(obj))
        {}

        virtual ~ResultData() {}

        const std::unique_ptr<TResult>& result() const {
            return result_;
        }

        virtual const std::exception* exception() const = 0;
        virtual std::unique_ptr<std::exception> move_exception() = 0;
    };

    template <>
    class ResultData<void> {
    public:
        ResultData() {}

        bool result() const {
            return (exception() == NULL);
        }
        virtual const std::exception* exception() const = 0;
        virtual std::unique_ptr<std::exception> move_exception() = 0;
    };

    template<typename TResult, class TException>
    class ResultImpl : public ResultData<TResult> {
    protected:
        friend class ResultBuilder<TResult, TException>;
        std::unique_ptr<TException> e_;

    public:
        ResultImpl()
                : ResultData()
        { }

        template<typename... Args>
        ResultImpl(Args&& ... eargs)
                : ResultData(eargs...)
        { }

        const std::exception* exception() const override {
            return e_.get();
        }

        std::unique_ptr<std::exception> move_exception() override {
            return std::move(e_);
        }
    };

    template<typename TResult>
    class ResultImpl<TResult, void> : public ResultData<TResult> {
    protected:
        friend class ResultBuilder<TResult, void>;

    public:
        ResultImpl()
                : ResultData()
        { }

        template<typename Arg>
        ResultImpl(std::unique_ptr<Arg> &arg)
            : ResultData(arg)
        { }

        template<typename... Args>
        ResultImpl(Args&& ... eargs)
                : ResultData(eargs...)
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
    class ResultImpl<void, TException> : public ResultData<void> {
    protected:
        friend class ResultBuilder<void, TException>;
        std::unique_ptr<TException> e_;

    public:
        ResultImpl()
                : ResultData()
        { }

        const std::exception* exception() const override {
            return e_.get();
        }

        std::unique_ptr<std::exception> move_exception() override {
            return std::move(e_);
        }
    };

    template<>
    class ResultImpl<void, void> : public ResultData<void> {
    protected:
        friend class ResultBuilder<void, void>;

    public:
        ResultImpl()
                : ResultData()
        { }

        const std::exception* exception() const override {
            return NULL;
        }

        std::unique_ptr<std::exception> move_exception() override {
            return NULL;
        }
    };


    template<typename TResult>
    class Result {
    private:
        std::unique_ptr<ResultData<TResult>> data_;
    public:
        Result() {}
        Result(const Result& rhs) = default;
        Result(Result&& rhs) = default;
        Result(std::unique_ptr<ResultData<TResult>> &&result_impl) : data_(std::move(result_impl)) { }
        void operator=(Result&& rhs) {
            data_ = std::move(rhs.data_);
        }
        const TResult *operator->() const {
            return &data_->result();
        }
        const TResult& operator*() const {
            return data_->result();
        }
        const TResult& result() const {
            return data_->result();
        }
        const std::exception* exception() const {
            return data_->exception();
        }
        std::unique_ptr<std::exception> move_exception() {
            return data_->move_exception();
        }
        operator bool() const {
            return !exception();
        }
    };

    template<>
    class Result<void> {
    private:
        std::unique_ptr<ResultData<void>> data_;
    public:
        Result() {}
        Result(const Result& rhs) = default;
        Result(Result&& rhs) = default;
        Result(std::unique_ptr<ResultData<void>> &&data) : data_(std::move(data)) { }
        const std::exception* exception() const {
            return data_->exception();
        }
        std::unique_ptr<std::exception> move_exception() {
            return data_->move_exception();
        }
        operator bool() const {
            return !exception();
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

        Result<TResult> build() {
            return Result<TResult>(std::move(result_));
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

        Result<void> build() {
            return Result<void>(std::move(result_));
        }
    };

    template<typename TResult>
    class ResultBuilder<TResult, void> {
    private:
        std::unique_ptr<ResultImpl<TResult, void>> result_;

    public:
        ResultBuilder(TResult &value) : result_(new ResultImpl<TResult, void>(value)) {
        }

        template<typename... RArgs>
        ResultBuilder(RArgs... args) : result_(new ResultImpl<TResult, void>(args...)) {
        }

        Result<TResult> build() {
            return Result<TResult>(std::move(result_));
        }
    };

    template<>
    class ResultBuilder<void, void> {
    private:
        std::unique_ptr<ResultImpl<void, void>> result_;

    public:
        ResultBuilder() : result_(new ResultImpl<void, void>()) {
        }

        Result<void> build() {
            return Result<void>(std::move(result_));
        }
    };

} // namespace src

