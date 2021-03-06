// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_DOWNLOAD_DOWNLOAD_PREFS_H_
#define CHROME_BROWSER_DOWNLOAD_DOWNLOAD_PREFS_H_
#pragma once

#include <set>

#include "base/file_path.h"
#include "chrome/browser/prefs/pref_member.h"

class PrefService;

// Stores all download-related preferences.
class DownloadPrefs {
 public:
  explicit DownloadPrefs(PrefService* prefs);
  ~DownloadPrefs();

  static void RegisterUserPrefs(PrefService* prefs);

  bool prompt_for_download() const { return *prompt_for_download_; }
  FilePath download_path() const { return *download_path_; }

  // Returns true if there is at least one file extension registered
  // for auto-open.
  bool IsAutoOpenUsed() const;

  bool IsAutoOpenEnabledForExtension(
      const FilePath::StringType& extension) const;

  // Enables auto-open based on file extension. Returns true on success.
  // TODO(phajdan.jr): Add WARN_UNUSED_RESULT here.
  bool EnableAutoOpenBasedOnExtension(const FilePath& file_name);

  // Disables auto-open based on file extension.
  void DisableAutoOpenBasedOnExtension(const FilePath& file_name);

  void ResetToDefaults();
  void ResetAutoOpen();

 private:
  void SaveAutoOpenState();

  PrefService* prefs_;

  BooleanPrefMember prompt_for_download_;
  FilePathPrefMember download_path_;

  // Set of file extensions to open at download completion.
  struct AutoOpenCompareFunctor {
    bool operator()(const FilePath::StringType& a,
                    const FilePath::StringType& b) const;
  };
  typedef std::set<FilePath::StringType, AutoOpenCompareFunctor> AutoOpenSet;
  AutoOpenSet auto_open_;

  DISALLOW_COPY_AND_ASSIGN(DownloadPrefs);
};

#endif  // CHROME_BROWSER_DOWNLOAD_DOWNLOAD_PREFS_H_
