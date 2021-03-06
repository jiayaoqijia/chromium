// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_EXTENSIONS_EXTERNAL_EXTENSION_LOADER_H_
#define CHROME_BROWSER_EXTENSIONS_EXTERNAL_EXTENSION_LOADER_H_
#pragma once

#include "base/file_path.h"
#include "base/ref_counted.h"
#include "base/scoped_ptr.h"

class DictionaryValue;
class ExternalExtensionProviderImpl;

// Base class for gathering a list of external extensions. Subclasses
// implement loading from registry, JSON file, policy.
// Instances are owned by ExternalExtensionProviderImpl objects.
// Instances are created on the UI thread and expect public method calls from
// the UI thread. Some subclasses introduce new methods that are executed on the
// FILE thread.
// The sequence of loading the extension list:
// 1.) StartLoading() - checks if a loading task is already running
// 2.) Load() - implemented in subclasses
// 3.) FinishLoading()
// 4.) owner_->SetPrefs()
class ExternalExtensionLoader
    : public base::RefCountedThreadSafe<ExternalExtensionLoader> {
 public:
  explicit ExternalExtensionLoader();

  // Specifies the provider that owns this object.
  void Init(ExternalExtensionProviderImpl* owner);

  // Called by the owner before it gets deleted.
  void OwnerShutdown();

  // Initiates the possibly asynchronous loading of extension list.
  // It is the responsibility of the caller to ensure that calls to
  // this method do not overlap with each other.
  // Implementations of this method should save the loaded results
  // in prefs_ and then call LoadFinished.
  virtual void StartLoading() = 0;

  // Some external providers allow relative file paths to local CRX files.
  // Subclasses that want this behavior should override this method to
  // return the absolute path from which relative paths should be resolved.
  // By default, return an empty path, which indicates that relative paths
  // are not allowed.
  virtual const FilePath GetBaseCrxFilePath();

 protected:
  virtual ~ExternalExtensionLoader();

  // Notifies the provider that the list of extensions has been loaded.
  void LoadFinished();

  // Used for passing the list of extensions from the method that loads them
  // to |LoadFinished|. To ensure thread safety, the rules are the following:
  // if this value is written on another thread than the UI, then it should
  // only be written in a task that was posted from |StartLoading|. After that,
  // this task should invoke |LoadFinished| with a PostTask. This scheme of
  // posting tasks will avoid concurrent access and imply the necessary memory
  // barriers.
  scoped_ptr<DictionaryValue> prefs_;

 private:
  friend class base::RefCountedThreadSafe<ExternalExtensionLoader>;

  ExternalExtensionProviderImpl* owner_;  // weak

  // Set to true if loading the extensions is already running. New requests
  // are ignored while this is set true.
  bool running_;

  DISALLOW_COPY_AND_ASSIGN(ExternalExtensionLoader);
};

#endif  // CHROME_BROWSER_EXTENSIONS_EXTERNAL_EXTENSION_LOADER_H_
