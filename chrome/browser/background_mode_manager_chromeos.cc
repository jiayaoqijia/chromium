// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/background_mode_manager.h"

#include "grit/generated_resources.h"
#include "ui/base/l10n/l10n_util.h"

void BackgroundModeManager::EnableLaunchOnStartup(bool should_launch) {
  NOTREACHED();
}

string16 BackgroundModeManager::GetPreferencesMenuLabel() {
  return l10n_util::GetStringUTF16(IDS_SETTINGS);
}
