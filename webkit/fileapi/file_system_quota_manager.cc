// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "webkit/fileapi/file_system_quota_manager.h"

#include "base/file_path.h"
#include "base/file_util_proxy.h"
#include "base/ref_counted.h"
#include "base/scoped_callback_factory.h"

namespace fileapi {

const int64 FileSystemQuotaManager::kUnknownSize = -1;

FileSystemQuotaManager::FileSystemQuotaManager(
    bool allow_file_access_from_files,
    bool unlimited_quota)
    : allow_file_access_from_files_(allow_file_access_from_files),
      unlimited_quota_(unlimited_quota) {
}

FileSystemQuotaManager::~FileSystemQuotaManager() {}

bool FileSystemQuotaManager::CheckOriginQuota(const GURL& origin, int64) {
  // If allow-file-access-from-files flag is explicitly given and the scheme
  // is file, or if unlimited quota for this process was explicitly requested,
  // return true.
  if (unlimited_quota_ ||
      (origin.SchemeIsFile() && allow_file_access_from_files_))
    return true;
  return CheckIfOriginGrantedUnlimitedQuota(origin);
}

void FileSystemQuotaManager::SetOriginQuotaUnlimited(const GURL& origin) {
  DCHECK(origin == origin.GetOrigin());
  unlimited_quota_origins_.insert(origin);
}

void FileSystemQuotaManager::ResetOriginQuotaUnlimited(const GURL& origin) {
  DCHECK(origin == origin.GetOrigin());
  unlimited_quota_origins_.erase(origin);
}

bool FileSystemQuotaManager::CheckIfOriginGrantedUnlimitedQuota(
    const GURL& origin) {
  std::set<GURL>::const_iterator found = unlimited_quota_origins_.find(origin);
  return (found != unlimited_quota_origins_.end());
}

}  // namespace fileapi
