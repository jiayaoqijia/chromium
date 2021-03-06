// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/auth.h"

namespace net {

const char kTLSSRPScheme[] = "tls-srp";

AuthChallengeInfo::AuthChallengeInfo() :
    is_proxy(false),
    over_protocol(AUTH_OVER_HTTP) {
}

bool AuthChallengeInfo::operator==(const AuthChallengeInfo& that) const {
  return (this->is_proxy == that.is_proxy &&
          this->host_and_port == that.host_and_port &&
          this->scheme == that.scheme &&
          this->realm == that.realm);
}

void AuthChallengeInfo::Reset() {
  is_proxy = false;
  host_and_port.clear();
  scheme.clear();
  realm.clear();
}

AuthChallengeInfo::~AuthChallengeInfo() {
}

AuthData::AuthData() :
    state(AUTH_STATE_NEED_AUTH),
    over_protocol(AUTH_OVER_HTTP) {
}

AuthData::~AuthData() {
}

}  // namespace net
