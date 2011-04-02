// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_TLS_CLIENT_LOGIN_CACHE_H_
#define NET_BASE_TLS_CLIENT_LOGIN_CACHE_H_
#pragma once

#include <string>
#include <map>

#include "base/ref_counted.h"
#include "net/base/auth.h"

namespace net {
  
// The TLSClientLoginCache class is a simple cache structure to store TLS
// client login credentials. Provides lookup, insertion, and deletion of
// entries. The parameter for doing lookups, insertions, and deletions is
// the server's host and port.
//
// TODO(wtc): This class is based on FtpAuthCache.  We can extract the common
// code to a template class.
class TLSClientLoginCache {
 public:
  TLSClientLoginCache();
  ~TLSClientLoginCache();

  // Checks for cached login credentials for TLS server at |server|.
  // Returns true if a preference is found, and sets |*tls_auth_data|
  // to the desired client login credentials.
  // If cached login credentials are not found, returns false.
  bool Lookup(const std::string& server,
              scoped_refptr<AuthData>* tls_auth_data);

  // Add client login credentials for |server| to the cache. If there are
  // already login credentials for |server|, they will be overwritten.
  void Add(const std::string& server, AuthData* tls_auth_data);

  // Remove the client certificate for |server| from the cache, if one exists.
  void Remove(const std::string& server);

 private:
  typedef std::string AuthCacheKey;
  typedef scoped_refptr<AuthData> AuthCacheValue;
  typedef std::map<AuthCacheKey, AuthCacheValue> AuthCacheMap;

  // internal representation of cache, an STL map.
  AuthCacheMap cache_;
};

}  // namespace net

#endif  // NET_BASE_TLS_CLIENT_LOGIN_CACHE_H_
