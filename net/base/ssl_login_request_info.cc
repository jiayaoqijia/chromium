// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/ssl_login_request_info.h"

namespace net {

SSLLoginRequestInfo::SSLLoginRequestInfo() {
}

void SSLLoginRequestInfo::Reset() {
  host_and_port.clear();
}

SSLLoginRequestInfo::~SSLLoginRequestInfo() {
}

}  // namespace net
