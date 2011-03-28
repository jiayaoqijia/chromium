// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SSL_LOGIN_REQUEST_INFO_H_
#define NET_BASE_SSL_LOGIN_REQUEST_INFO_H_
#pragma once

#include <string>
#include <vector>

#include "base/ref_counted.h"

namespace net {

// The SSLLoginRequestInfo class contains the info that allows a user to
// choose credentials to send to the SSL server for client authentication.
class SSLLoginRequestInfo
    : public base::RefCountedThreadSafe<SSLLoginRequestInfo> {
 public:
  SSLLoginRequestInfo();

  void Reset();

  // The host and port of the SSL server that requested client authentication.
  std::string host_and_port;

 private:
  friend class base::RefCountedThreadSafe<SSLLoginRequestInfo>;

  ~SSLLoginRequestInfo();
};

}  // namespace net

#endif  // NET_BASE_SSL_LOGIN_REQUEST_INFO_H_
