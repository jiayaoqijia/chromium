// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_error_job.h"

#include "base/message_loop.h"
#include "net/base/net_errors.h"
#include "net/url_request/url_request_status.h"

namespace net {

URLRequestErrorJob::URLRequestErrorJob(URLRequest* request, int error)
    : URLRequestJob(request), error_(error) {
}

void URLRequestErrorJob::Start() {
  MessageLoop::current()->PostTask(FROM_HERE, NewRunnableMethod(
      this, &URLRequestErrorJob::StartAsync));
}

void URLRequestErrorJob::StartAsync() {
  NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, error_));
}

}  // namespace net
