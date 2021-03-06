// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/prefs/scoped_pref_update.h"

#include "chrome/browser/prefs/pref_notifier.h"
#include "chrome/browser/prefs/pref_service.h"

ScopedPrefUpdate::ScopedPrefUpdate(PrefService* service, const char* path)
    : service_(service),
      path_(path) {}

ScopedPrefUpdate::~ScopedPrefUpdate() {
  // TODO(mnissler, danno): This sends a notification unconditionally, which is
  // wrong. We should rather tell the PrefService that the user pref got
  // updated.
  service_->pref_notifier()->OnPreferenceChanged(path_.c_str());
}
