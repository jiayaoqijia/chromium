// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_AUTH_H__
#define NET_BASE_AUTH_H__
#pragma once

#include <string>

#include "base/ref_counted.h"
#include "base/string16.h"

namespace net {

extern const char kTLSSRPScheme[];

// Protocols that use authentication
enum AuthOverProtocol {
  AUTH_OVER_HTTP,
  AUTH_OVER_TLS
};

// Holds info about an authentication challenge that we may want to display
// to the user.
class AuthChallengeInfo :
    public base::RefCountedThreadSafe<AuthChallengeInfo> {
 public:
  AuthChallengeInfo();

  void Reset();

  bool operator==(const AuthChallengeInfo& that) const;

  bool operator!=(const AuthChallengeInfo& that) const {
    return !(*this == that);
  }

  bool is_proxy;  // true for Proxy-Authenticate, false for WWW-Authenticate.
  std::wstring host_and_port;  // <host>:<port> of the server asking for auth
                               // (could be the proxy).
  std::wstring scheme;  // "Basic", "Digest", or whatever other method is used.
  std::wstring realm;  // the realm provided by the server, if there is one.

  int over_protocol; // the protocol to authenticate over (HTTP or TLS).

 private:
  friend class base::RefCountedThreadSafe<AuthChallengeInfo>;
  ~AuthChallengeInfo();
};

// Authentication structures
enum AuthState {
  AUTH_STATE_DONT_NEED_AUTH,
  AUTH_STATE_NEED_AUTH,
  AUTH_STATE_HAVE_AUTH,
  AUTH_STATE_CANCELED
};

class AuthData : public base::RefCountedThreadSafe<AuthData> {
 public:
  AuthState state;  // whether we need, have, or gave up on authentication.
  std::wstring scheme;  // the authentication scheme.
  string16 username;  // the username supplied to us for auth.
  string16 password;  // the password supplied to us for auth.
  int over_protocol; // the protocol to authenticate over (HTTP or TLS).

  // We wouldn't instantiate this class if we didn't need authentication.
  AuthData();

 private:
  friend class base::RefCountedThreadSafe<AuthData>;
  ~AuthData();
};

}  // namespace net

#endif  // NET_BASE_AUTH_H__
