// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_ACCESSIBILITY_BROWSER_ACCESSIBILITY_MANAGER_WIN_H_
#define CHROME_BROWSER_ACCESSIBILITY_BROWSER_ACCESSIBILITY_MANAGER_WIN_H_
#pragma once

#include <oleacc.h>

#include "base/scoped_comptr_win.h"
#include "chrome/browser/accessibility/browser_accessibility_manager.h"
#include "chrome/common/render_messages_params.h"
#include "webkit/glue/webaccessibility.h"

class BrowserAccessibilityWin;
struct ViewHostMsg_AccessibilityNotification_Params;

using webkit_glue::WebAccessibility;

// Manages a tree of BrowserAccessibilityWin objects.
class BrowserAccessibilityManagerWin : public BrowserAccessibilityManager {
 public:
  virtual ~BrowserAccessibilityManagerWin();

  // Get a the default IAccessible for the parent window, does not make a
  // new reference.
  IAccessible* GetParentWindowIAccessible();

  // BrowserAccessibilityManager methods
  virtual void NotifyAccessibilityEvent(
      ViewHostMsg_AccessibilityNotification_Params::NotificationType n,
      BrowserAccessibility* node);

 private:
  BrowserAccessibilityManagerWin(
      HWND parent_window,
      const WebAccessibility& src,
      BrowserAccessibilityDelegate* delegate,
      BrowserAccessibilityFactory* factory);

  // A default IAccessible instance for the parent window.
  ScopedComPtr<IAccessible> window_iaccessible_;

  // Give BrowserAccessibilityManager::Create access to our constructor.
  friend class BrowserAccessibilityManager;

  DISALLOW_COPY_AND_ASSIGN(BrowserAccessibilityManagerWin);
};

#endif  // CHROME_BROWSER_ACCESSIBILITY_BROWSER_ACCESSIBILITY_MANAGER_WIN_H_
