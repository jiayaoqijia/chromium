// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/browsing_data_local_storage_helper.h"

#include "base/file_util.h"
#include "base/message_loop.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "chrome/browser/browser_thread.h"
#include "chrome/browser/in_process_webkit/webkit_context.h"
#include "chrome/browser/profiles/profile.h"
#include "third_party/WebKit/Source/WebKit/chromium/public/WebCString.h"
#include "third_party/WebKit/Source/WebKit/chromium/public/WebSecurityOrigin.h"
#include "third_party/WebKit/Source/WebKit/chromium/public/WebString.h"
#include "webkit/glue/webkit_glue.h"

BrowsingDataLocalStorageHelper::LocalStorageInfo::LocalStorageInfo() {}

BrowsingDataLocalStorageHelper::LocalStorageInfo::LocalStorageInfo(
    const std::string& protocol,
    const std::string& host,
    unsigned short port,
    const std::string& database_identifier,
    const std::string& origin,
    const FilePath& file_path,
    int64 size,
    base::Time last_modified)
    : protocol(protocol),
      host(host),
      port(port),
      database_identifier(database_identifier),
      origin(origin),
      file_path(file_path),
      size(size),
      last_modified(last_modified) {
      }

BrowsingDataLocalStorageHelper::LocalStorageInfo::~LocalStorageInfo() {}

BrowsingDataLocalStorageHelper::BrowsingDataLocalStorageHelper(
    Profile* profile)
    : profile_(profile),
      completion_callback_(NULL),
      is_fetching_(false) {
  DCHECK(profile_);
}

BrowsingDataLocalStorageHelper::~BrowsingDataLocalStorageHelper() {
}

void BrowsingDataLocalStorageHelper::StartFetching(
    Callback1<const std::vector<LocalStorageInfo>& >::Type* callback) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
  DCHECK(!is_fetching_);
  DCHECK(callback);
  is_fetching_ = true;
  completion_callback_.reset(callback);
  BrowserThread::PostTask(
      BrowserThread::WEBKIT, FROM_HERE,
      NewRunnableMethod(
          this,
          &BrowsingDataLocalStorageHelper::
              FetchLocalStorageInfoInWebKitThread));
}

void BrowsingDataLocalStorageHelper::CancelNotification() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
  completion_callback_.reset(NULL);
}

void BrowsingDataLocalStorageHelper::DeleteLocalStorageFile(
    const FilePath& file_path) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
  BrowserThread::PostTask(
      BrowserThread::WEBKIT, FROM_HERE,
       NewRunnableMethod(
           this,
           &BrowsingDataLocalStorageHelper::
              DeleteLocalStorageFileInWebKitThread,
           file_path));
}

void BrowsingDataLocalStorageHelper::FetchLocalStorageInfoInWebKitThread() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::WEBKIT));
  file_util::FileEnumerator file_enumerator(
      profile_->GetWebKitContext()->data_path().Append(
          DOMStorageContext::kLocalStorageDirectory),
      false, file_util::FileEnumerator::FILES);
  for (FilePath file_path = file_enumerator.Next(); !file_path.empty();
       file_path = file_enumerator.Next()) {
    if (file_path.Extension() == DOMStorageContext::kLocalStorageExtension) {
      WebKit::WebSecurityOrigin web_security_origin =
          WebKit::WebSecurityOrigin::createFromDatabaseIdentifier(
              webkit_glue::FilePathToWebString(file_path.BaseName()));
      if (EqualsASCII(web_security_origin.protocol(),
                      chrome::kExtensionScheme)) {
        // Extension state is not considered browsing data.
        continue;
      }
      base::PlatformFileInfo file_info;
      bool ret = file_util::GetFileInfo(file_path, &file_info);
      if (ret) {
        local_storage_info_.push_back(LocalStorageInfo(
            web_security_origin.protocol().utf8(),
            web_security_origin.host().utf8(),
            web_security_origin.port(),
            web_security_origin.databaseIdentifier().utf8(),
            web_security_origin.toString().utf8(),
            file_path,
            file_info.size,
            file_info.last_modified));
      }
    }
  }

  BrowserThread::PostTask(
      BrowserThread::UI, FROM_HERE,
      NewRunnableMethod(
          this, &BrowsingDataLocalStorageHelper::NotifyInUIThread));
}

void BrowsingDataLocalStorageHelper::NotifyInUIThread() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
  DCHECK(is_fetching_);
  // Note: completion_callback_ mutates only in the UI thread, so it's safe to
  // test it here.
  if (completion_callback_ != NULL) {
    completion_callback_->Run(local_storage_info_);
    completion_callback_.reset();
  }
  is_fetching_ = false;
}

void BrowsingDataLocalStorageHelper::DeleteLocalStorageFileInWebKitThread(
    const FilePath& file_path) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::WEBKIT));
  profile_->GetWebKitContext()->dom_storage_context()->DeleteLocalStorageFile(
      file_path);
}

CannedBrowsingDataLocalStorageHelper::CannedBrowsingDataLocalStorageHelper(
    Profile* profile)
    : BrowsingDataLocalStorageHelper(profile) {
}

void CannedBrowsingDataLocalStorageHelper::AddLocalStorage(
    const GURL& origin) {
  WebKit::WebSecurityOrigin web_security_origin =
      WebKit::WebSecurityOrigin::createFromString(
          UTF8ToUTF16(origin.spec()));
  std::string security_origin(web_security_origin.toString().utf8());

  for (std::vector<LocalStorageInfo>::iterator
       local_storage = local_storage_info_.begin();
       local_storage != local_storage_info_.end(); ++local_storage) {
    if (local_storage->origin == security_origin)
      return;
  }

  local_storage_info_.push_back(LocalStorageInfo(
      web_security_origin.protocol().utf8(),
      web_security_origin.host().utf8(),
      web_security_origin.port(),
      web_security_origin.databaseIdentifier().utf8(),
      security_origin,
      profile_->GetWebKitContext()->dom_storage_context()->
          GetLocalStorageFilePath(web_security_origin.databaseIdentifier()),
      0,
      base::Time()));
}

void CannedBrowsingDataLocalStorageHelper::Reset() {
  local_storage_info_.clear();
}

bool CannedBrowsingDataLocalStorageHelper::empty() const {
  return local_storage_info_.empty();
}

void CannedBrowsingDataLocalStorageHelper::StartFetching(
    Callback1<const std::vector<LocalStorageInfo>& >::Type* callback) {
  callback->Run(local_storage_info_);
  delete callback;
}
