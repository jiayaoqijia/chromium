// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_INFOBARS_LINK_INFOBAR_H_
#define CHROME_BROWSER_UI_VIEWS_INFOBARS_LINK_INFOBAR_H_
#pragma once

#include "chrome/browser/ui/views/infobars/infobar_view.h"
#include "views/controls/link.h"

class LinkInfoBarDelegate;

// An infobar that shows a string with an embedded link.
class LinkInfoBar : public InfoBarView,
                    public views::LinkController {
 public:
  explicit LinkInfoBar(LinkInfoBarDelegate* delegate);
  virtual ~LinkInfoBar();

  // Overridden from views::LinkController:
  virtual void LinkActivated(views::Link* source, int event_flags);

  // Overridden from views::View:
  virtual void Layout();

 private:
  LinkInfoBarDelegate* GetDelegate();

  views::ImageView* icon_;
  views::Label* label_1_;
  views::Label* label_2_;
  views::Link* link_;

  DISALLOW_COPY_AND_ASSIGN(LinkInfoBar);
};

#endif  // CHROME_BROWSER_UI_VIEWS_INFOBARS_LINK_INFOBAR_H_
