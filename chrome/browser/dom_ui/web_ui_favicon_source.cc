// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/dom_ui/web_ui_favicon_source.h"

#include "base/callback.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/common/url_constants.h"
#include "grit/app_resources.h"
#include "ui/base/resource/resource_bundle.h"

WebUIFavIconSource::WebUIFavIconSource(Profile* profile)
    : DataSource(chrome::kChromeUIFavIconHost, MessageLoop::current()),
      profile_(profile->GetOriginalProfile()) {
}

WebUIFavIconSource::~WebUIFavIconSource() {
}

void WebUIFavIconSource::StartDataRequest(const std::string& path,
                                          bool is_off_the_record,
                                          int request_id) {
  FaviconService* favicon_service =
      profile_->GetFaviconService(Profile::EXPLICIT_ACCESS);
  if (favicon_service) {
    FaviconService::Handle handle;
    if (path.empty()) {
      SendDefaultResponse(request_id);
      return;
    }

    if (path.size() > 8 && path.substr(0, 8) == "iconurl/") {
      handle = favicon_service->GetFavicon(
          GURL(path.substr(8)),
          &cancelable_consumer_,
          NewCallback(this, &WebUIFavIconSource::OnFavIconDataAvailable));
    } else {
      handle = favicon_service->GetFaviconForURL(
          GURL(path),
          &cancelable_consumer_,
          NewCallback(this, &WebUIFavIconSource::OnFavIconDataAvailable));
    }
    // Attach the ChromeURLDataManager request ID to the history request.
    cancelable_consumer_.SetClientData(favicon_service, handle, request_id);
  } else {
    SendResponse(request_id, NULL);
  }
}

std::string WebUIFavIconSource::GetMimeType(const std::string&) const {
  // We need to explicitly return a mime type, otherwise if the user tries to
  // drag the image they get no extension.
  return "image/png";
}

void WebUIFavIconSource::OnFavIconDataAvailable(
    FaviconService::Handle request_handle,
    bool know_favicon,
    scoped_refptr<RefCountedMemory> data,
    bool expired,
    GURL icon_url) {
  FaviconService* favicon_service =
      profile_->GetFaviconService(Profile::EXPLICIT_ACCESS);
  int request_id = cancelable_consumer_.GetClientData(favicon_service,
                                                      request_handle);

  if (know_favicon && data.get() && data->size()) {
    // Forward the data along to the networking system.
    SendResponse(request_id, data);
  } else {
    SendDefaultResponse(request_id);
  }
}

void WebUIFavIconSource::SendDefaultResponse(int request_id) {
  if (!default_favicon_.get()) {
    default_favicon_ =
        ResourceBundle::GetSharedInstance().LoadDataResourceBytes(
            IDR_DEFAULT_FAVICON);
  }

  SendResponse(request_id, default_favicon_);
}
