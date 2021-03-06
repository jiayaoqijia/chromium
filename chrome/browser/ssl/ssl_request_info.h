// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SSL_SSL_REQUEST_INFO_H_
#define CHROME_BROWSER_SSL_SSL_REQUEST_INFO_H_
#pragma once

#include <string>

#include "base/ref_counted.h"
#include "googleurl/src/gurl.h"
#include "webkit/glue/resource_type.h"

// SSLRequestInfo wraps up the information SSLPolicy needs about a request in
// order to update our security IU.  SSLRequestInfo is RefCounted in case we
// need to deal with the request asynchronously.
class SSLRequestInfo : public base::RefCounted<SSLRequestInfo> {
 public:
  SSLRequestInfo(const GURL& url,
                 ResourceType::Type resource_type,
                 const std::string& frame_origin,
                 const std::string& main_frame_origin,
                 int child_id,
                 int ssl_cert_id,
                 int ssl_cert_status,
                 string16 tls_username);

  const GURL& url() const { return url_; }
  ResourceType::Type resource_type() const { return resource_type_; }
  const std::string& frame_origin() const { return frame_origin_; }
  const std::string& main_frame_origin() const { return main_frame_origin_; }
  int child_id() const { return child_id_; }
  int ssl_cert_id() const { return ssl_cert_id_; }
  int ssl_cert_status() const { return ssl_cert_status_; }
  string16 tls_username() const { return tls_username_; }

 private:
  friend class base::RefCounted<SSLRequestInfo>;

  virtual ~SSLRequestInfo();

  GURL url_;
  ResourceType::Type resource_type_;
  std::string frame_origin_;
  std::string main_frame_origin_;
  int child_id_;
  int ssl_cert_id_;
  int ssl_cert_status_;
  string16 tls_username_;

  DISALLOW_COPY_AND_ASSIGN(SSLRequestInfo);
};

#endif  // CHROME_BROWSER_SSL_SSL_REQUEST_INFO_H_
