// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_DOM_UI_OPTIONS_ADVANCED_OPTIONS_UTILS_H_
#define CHROME_BROWSER_DOM_UI_OPTIONS_ADVANCED_OPTIONS_UTILS_H_

#include "base/basictypes.h"

class TabContents;

// Chrome advanced options utility methods.
class AdvancedOptionsUtilities {
 public:
  // Invoke UI for network proxy settings.
  static void ShowNetworkProxySettings(TabContents*);

  // Invoke UI for SSL certificates.
  static void ShowManageSSLCertificates(TabContents*);

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(AdvancedOptionsUtilities);
};

#endif  // CHROME_BROWSER_DOM_UI_OPTIONS_ADVANCED_OPTIONS_UTILS_H_
