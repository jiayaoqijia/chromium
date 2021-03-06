// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UI_BASE_X_X11_UTIL_INTERNAL_H_
#define UI_BASE_X_X11_UTIL_INTERNAL_H_
#pragma once

// This file declares utility functions for X11 (Linux only).
//
// These functions require the inclusion of the Xlib headers. Since the Xlib
// headers pollute so much of the namespace, this should only be included
// when needed.

extern "C" {
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/Xrender.h>
}

namespace ui {

  // --------------------------------------------------------------------------
  // NOTE: these functions cache the results and must be called from the UI
  // thread.
  // Get the XRENDER format id for ARGB32 (Skia's format).
  //
  // NOTE:Currently this don't support multiple screens/displays.
  XRenderPictFormat* GetRenderARGB32Format(Display* dpy);

  // Get the XRENDER format id for the default visual on the first screen. This
  // is the format which our GTK window will have.
  XRenderPictFormat* GetRenderVisualFormat(Display* dpy, Visual* visual);

  // --------------------------------------------------------------------------
  // X11 error handling.
  // Sets the X Error Handlers. Passing NULL for either will enable the default
  // error handler, which if called will log the error and abort the process.
  void SetX11ErrorHandlers(XErrorHandler error_handler,
                           XIOErrorHandler io_error_handler);

  // Returns a string suitable for logging the error event.
  std::string GetErrorEventDescription(Display* dpy, XErrorEvent* error_event);

}  // namespace ui

#endif  // UI_BASE_X_X11_UTIL_INTERNAL_H_
