// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_DOM_UI_WEB_UI_FAVICON_SOURCE_H_
#define CHROME_BROWSER_DOM_UI_WEB_UI_FAVICON_SOURCE_H_
#pragma once

#include <string>

#include "base/basictypes.h"
#include "base/ref_counted.h"
#include "chrome/browser/dom_ui/chrome_url_data_manager.h"
#include "chrome/browser/favicon_service.h"

class GURL;
class Profile;

// FavIconSource is the gateway between network-level chrome:
// requests for favicons and the history backend that serves these.
class WebUIFavIconSource : public ChromeURLDataManager::DataSource {
 public:
  explicit WebUIFavIconSource(Profile* profile);

  // Called when the network layer has requested a resource underneath
  // the path we registered.
  virtual void StartDataRequest(const std::string& path,
                                bool is_off_the_record,
                                int request_id);

  virtual std::string GetMimeType(const std::string&) const;

  // Called when favicon data is available from the history backend.
  void OnFavIconDataAvailable(FaviconService::Handle request_handle,
                              bool know_favicon,
                              scoped_refptr<RefCountedMemory> data,
                              bool expired,
                              GURL url);

 private:
  // Sends the default favicon.
  void SendDefaultResponse(int request_id);

  virtual ~WebUIFavIconSource();

  Profile* profile_;
  CancelableRequestConsumerT<int, 0> cancelable_consumer_;

  // Raw PNG representation of the favicon to show when the favicon
  // database doesn't have a favicon for a webpage.
  scoped_refptr<RefCountedMemory> default_favicon_;

  DISALLOW_COPY_AND_ASSIGN(WebUIFavIconSource);
};

#endif  // CHROME_BROWSER_DOM_UI_WEB_UI_FAVICON_SOURCE_H_
