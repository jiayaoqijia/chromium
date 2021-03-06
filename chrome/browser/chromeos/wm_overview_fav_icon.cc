// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/wm_overview_fav_icon.h"

#include <vector>

#include "chrome/browser/chromeos/wm_ipc.h"
#include "chrome/browser/chromeos/wm_overview_snapshot.h"
#include "skia/ext/image_operations.h"
#include "third_party/cros/chromeos_wm_ipc_enums.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/base/x/x11_util.h"
#include "views/controls/image_view.h"
#include "views/controls/label.h"
#include "views/layout/grid_layout.h"

using std::vector;

#if !defined(OS_CHROMEOS)
#error This file is only meant to be compiled for ChromeOS
#endif

namespace chromeos {

const int WmOverviewFavIcon::kIconSize = 32;

WmOverviewFavIcon::WmOverviewFavIcon()
    : WidgetGtk(TYPE_WINDOW),
      fav_icon_view_(NULL) {
}

void WmOverviewFavIcon::Init(WmOverviewSnapshot* snapshot) {
  MakeTransparent();

  fav_icon_view_ = new views::ImageView();

  WidgetGtk::Init(NULL, gfx::Rect(0, 0, 0, 0));

  SetContentsView(fav_icon_view_);

  // Set the window type
  vector<int> params;
  params.push_back(ui::GetX11WindowFromGtkWidget(
      GTK_WIDGET(snapshot->GetNativeView())));
  WmIpc::instance()->SetWindowType(
      GetNativeView(),
      WM_IPC_WINDOW_CHROME_TAB_FAV_ICON,
      &params);
}


void WmOverviewFavIcon::SetFavIcon(const SkBitmap& image) {
  CHECK(fav_icon_view_) << "Init not called before setting fav icon.";
  SkBitmap icon;
  if (image.width() && image.height()) {
    float aspect_ratio = static_cast<float>(image.width()) / image.height();
    int new_width = kIconSize;
    int new_height = kIconSize;
    if (aspect_ratio > 1.0f) {
      new_height = kIconSize / aspect_ratio;
    } else {
      new_width = kIconSize * aspect_ratio;
    }
    if (new_width && new_height) {
      icon = skia::ImageOperations::Resize(
          image, skia::ImageOperations::RESIZE_BOX,
          new_width, new_height);
    }
  }

  fav_icon_view_->SetImage(icon);

  // Reset the bounds to the size of the image.
  gfx::Rect bounds;
  GetBounds(&bounds, false);
  bounds.set_width(icon.width());
  bounds.set_height(icon.height());
  SetBounds(bounds);
}

}  // namespace chromeos
