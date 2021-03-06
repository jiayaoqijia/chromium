// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_GTK_IMPORT_LOCK_DIALOG_GTK_H_
#define CHROME_BROWSER_UI_GTK_IMPORT_LOCK_DIALOG_GTK_H_
#pragma once

#include <gtk/gtk.h>

#include "base/basictypes.h"
#include "base/ref_counted.h"
#include "ui/base/gtk/gtk_signal.h"

class ImporterHost;

class ImportLockDialogGtk {
 public:
  // Displays the Firefox profile locked warning
  static void Show(GtkWindow* parent, ImporterHost* importer_host);

 private:
  ImportLockDialogGtk(GtkWindow* parent, ImporterHost* importer_host);
  ~ImportLockDialogGtk();

  CHROMEGTK_CALLBACK_1(ImportLockDialogGtk, void, OnDialogResponse, int);

  // Dialog box
  GtkWidget* dialog_;

  // Utility class that does the actual import.
  scoped_refptr<ImporterHost> importer_host_;

  DISALLOW_COPY_AND_ASSIGN(ImportLockDialogGtk);
};

#endif  // CHROME_BROWSER_UI_GTK_IMPORT_LOCK_DIALOG_GTK_H_
