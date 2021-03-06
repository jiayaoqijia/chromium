// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_RENDERER_HOST_BACKING_STORE_WIN_H_
#define CHROME_BROWSER_RENDERER_HOST_BACKING_STORE_WIN_H_
#pragma once

#include <windows.h>

#include "base/basictypes.h"
#include "chrome/browser/renderer_host/backing_store.h"

class BackingStoreWin : public BackingStore {
 public:
  BackingStoreWin(RenderWidgetHost* widget, const gfx::Size& size);
  virtual ~BackingStoreWin();

  HDC hdc() { return hdc_; }

  // Returns true if we should convert to the monitor profile when painting.
  static bool ColorManagementEnabled();

  // BackingStore implementation.
  virtual size_t MemorySize();
  virtual void PaintToBackingStore(RenderProcessHost* process,
                                   TransportDIB::Id bitmap,
                                   const gfx::Rect& bitmap_rect,
                                   const std::vector<gfx::Rect>& copy_rects);
  virtual bool CopyFromBackingStore(const gfx::Rect& rect,
                                    skia::PlatformCanvas* output);
  virtual void ScrollBackingStore(int dx, int dy,
                                  const gfx::Rect& clip_rect,
                                  const gfx::Size& view_size);

 private:
  // The backing store dc.
  HDC hdc_;

  // Handle to the backing store dib.
  HANDLE backing_store_dib_;

  // Handle to the original bitmap in the dc.
  HANDLE original_bitmap_;

  // Number of bits per pixel of the screen.
  int color_depth_;

  DISALLOW_COPY_AND_ASSIGN(BackingStoreWin);
};

#endif  // CHROME_BROWSER_RENDERER_HOST_BACKING_STORE_WIN_H_
