// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/tls_client_login_cache.h"

#include "base/logging.h"

namespace net {

TLSClientLoginCache::TLSClientLoginCache() {}

TLSClientLoginCache::~TLSClientLoginCache() {}

bool TLSClientLoginCache::Lookup(
    const std::string& server,
    scoped_refptr<AuthData>* tls_auth_data) {
  DCHECK(tls_auth_data);

  AuthCacheMap::iterator iter = cache_.find(server);
  if (iter == cache_.end())
    return false;

  *tls_auth_data = iter->second;
  return true;
}

void TLSClientLoginCache::Add(const std::string& server,
                              AuthData* tls_auth_data) {
  cache_[server] = tls_auth_data;

  // TODO(wtc): enforce a maximum number of entries.
}

void TLSClientLoginCache::Remove(const std::string& server) {
  cache_.erase(server);
}

}  // namespace net
