// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TAB_CONTENTS_NATIVE_TAB_CONTENTS_CONTAINER_GTK_H_
#define CHROME_BROWSER_UI_VIEWS_TAB_CONTENTS_NATIVE_TAB_CONTENTS_CONTAINER_GTK_H_
#pragma once

#include <gtk/gtk.h>

#include "chrome/browser/ui/views/tab_contents/native_tab_contents_container.h"
#include "views/controls/native/native_view_host.h"

class NativeTabContentsContainerGtk : public NativeTabContentsContainer,
                                      public views::NativeViewHost {
 public:
  explicit NativeTabContentsContainerGtk(TabContentsContainer* container);
  virtual ~NativeTabContentsContainerGtk();

  // Overridden from NativeTabContentsContainer:
  virtual void AttachContents(TabContents* contents);
  virtual void DetachContents(TabContents* contents);
  virtual void SetFastResize(bool fast_resize);
  virtual void RenderViewHostChanged(RenderViewHost* old_host,
                                     RenderViewHost* new_host);
  virtual void TabContentsFocused(TabContents* tab_contents);
  virtual views::View* GetView();

  // Overridden from views::View:
  virtual bool SkipDefaultKeyEventProcessing(const views::KeyEvent& e);
  virtual views::FocusTraversable* GetFocusTraversable();
  virtual bool IsFocusable() const;
  virtual void Focus();
  virtual void RequestFocus();
  virtual void AboutToRequestFocusFromTabTraversal(bool reverse);
  virtual AccessibilityTypes::Role GetAccessibleRole();

 private:
  TabContentsContainer* container_;

  gulong focus_callback_id_;

  DISALLOW_COPY_AND_ASSIGN(NativeTabContentsContainerGtk);
};

#endif  // CHROME_BROWSER_UI_VIEWS_TAB_CONTENTS_NATIVE_TAB_CONTENTS_CONTAINER_GTK_H_
