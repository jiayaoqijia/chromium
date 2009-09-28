// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_MAIN_MENU_H_
#define CHROME_BROWSER_CHROMEOS_MAIN_MENU_H_

#include <gtk/gtk.h>

#include "base/scoped_ptr.h"
#include "chrome/browser/renderer_host/render_view_host_delegate.h"
#include "chrome/browser/tab_contents/render_view_host_delegate_helper.h"
#include "chrome/browser/tab_contents/tab_contents_delegate.h"

class Browser;
class RenderWidgetHostViewGtk;
class SiteInstance;

namespace views {
class WidgetGtk;
}

// MainMenu manages showing the main menu. The menu is currently an HTML page.
// When the user clicks a link on the page a new tab is added to the current
// browser and the menu is hidden.
//
// To show the menu invoke Show.
//
// MainMenu creates a RenderViewHost and corresponding RenderWidgetHostView
// to display the html page. MainMenu acts as the RenderViewHostDelegate for
// the RenderViewHost. Clicking on a link results in creating a new
// TabContents (assigned to pending_contents_). One of two things can then
// happen:
// . If the page is a popup (ShowCreatedWindow passed NEW_POPUP), the
//   TabContents is added to the Browser.
// . If the page requests a URL to be open (OpenURLFromTab), OpenURL is
//   invoked on the browser.
//
// When a new url is opened, or the user clicks outsides the bounds of the
// widget the menu is closed.
//
// MainMenu manages its own lifetime. In some cases deletion is delayed because
// the callers can't deal with being deleted while servicing a message from
// the renderer.
class MainMenu : public RenderViewHostDelegate,
                 public RenderViewHostDelegate::View {
 public:
  // Shows the menu.
  static void Show(Browser* browser);

  ~MainMenu();

 private:
  // TabContentsDelegate and RenderViewHostDelegate::View have some methods
  // in common (with differing signatures). The TabContentsDelegate methods are
  // implemented by this class.
  class TabContentsDelegateImpl : public TabContentsDelegate {
   public:
    explicit TabContentsDelegateImpl(MainMenu* menu) : menu_(menu) {}

    // TabContentsDelegate.
    virtual void OpenURLFromTab(TabContents* source,
                                const GURL& url, const GURL& referrer,
                                WindowOpenDisposition disposition,
                                PageTransition::Type transition);
    virtual void NavigationStateChanged(const TabContents* source,
                                        unsigned changed_flags) {}
    virtual void AddNewContents(TabContents* source,
                                TabContents* new_contents,
                                WindowOpenDisposition disposition,
                                const gfx::Rect& initial_pos,
                                bool user_gesture) {}
    virtual void ActivateContents(TabContents* contents) {}
    virtual void LoadingStateChanged(TabContents* source) {}
    virtual void CloseContents(TabContents* source) {}
    virtual void MoveContents(TabContents* source, const gfx::Rect& pos) {}
    virtual bool IsPopup(TabContents* source) { return false; }
    virtual void ToolbarSizeChanged(TabContents* source, bool is_animating) {}
    virtual void URLStarredChanged(TabContents* source, bool starred) {}
    virtual void UpdateTargetURL(TabContents* source, const GURL& url) {}

   private:
    MainMenu* menu_;

    DISALLOW_COPY_AND_ASSIGN(TabContentsDelegateImpl);
  };

  friend class TabContentsDelegateImpl;

  explicit MainMenu(Browser* browser);

  void ShowImpl();

  // Does cleanup before deletion. If |now| is true delete is invoked
  // immediately, otherwise deletion occurs after a delay. See description
  // above class as to why we need to delay deletion in some situations.
  void Delete(bool now);

  // Callback from button presses on the render widget host view. Clicks
  // outside the widget resulting in closing the menu.
  static gboolean CallButtonPressEvent(GtkWidget* widget,
                                       GdkEventButton* event,
                                       MainMenu* menu);
  gboolean OnButtonPressEvent(GtkWidget* widget,
                              GdkEventButton* event);

  // RenderViewHostDelegate overrides.
  virtual int GetBrowserWindowID() const {
    return -1;
  }
  virtual ViewType::Type GetRenderViewType() const {
    return ViewType::INVALID;
  }
  virtual RenderViewHostDelegate::View* GetViewDelegate() {
    return this;
  }
  virtual void RequestMove(const gfx::Rect& new_bounds);

  // RenderViewHostDelegate::View overrides.
  virtual void CreateNewWindow(int route_id,
                               base::WaitableEvent* modal_dialog_event);
  virtual void CreateNewWidget(int route_id, bool activatable) {}
  virtual void ShowCreatedWindow(int route_id,
                                 WindowOpenDisposition disposition,
                                 const gfx::Rect& initial_pos,
                                 bool user_gesture,
                                 const GURL& creator_url);
  virtual void ShowCreatedWidget(int route_id,
                                 const gfx::Rect& initial_pos) {}
  virtual void ShowContextMenu(const ContextMenuParams& params) {}
  virtual void StartDragging(const WebDropData& drop_data,
                             WebKit::WebDragOperationsMask allowed_ops) {}
  virtual void UpdateDragCursor(WebKit::WebDragOperation operation) {}
  virtual void GotFocus() {}
  virtual void TakeFocus(bool reverse) {}
  virtual void HandleKeyboardEvent(const NativeWebKeyboardEvent& event) {}
  virtual void HandleMouseEvent() {}
  virtual void HandleMouseLeave() {}
  virtual void UpdatePreferredWidth(int pref_width) {}

  // The currently active browser. We use this to open urls.
  Browser* browser_;

  // The widget displaying the rwvh_.
  views::WidgetGtk* popup_;

  // SiteInstance for the RenderViewHosts we create.
  SiteInstance* site_instance_;

  // RenderViewHost for the menu.
  RenderViewHost* menu_rvh_;

  // RenderWidgetHostView from the menu_rvh_.
  RenderWidgetHostViewGtk* rwhv_;

  // Handles creating the child TabContents.
  RenderViewHostDelegateViewHelper helper_;

  // Delegate of the TabContents created by helper_.
  TabContentsDelegateImpl tab_contents_delegate_;

  // TabContents created when the user clicks a link.
  scoped_ptr<TabContents> pending_contents_;

  DISALLOW_COPY_AND_ASSIGN(MainMenu);
};

#endif  // CHROME_BROWSER_CHROMEOS_CHROMEOS_VERSION_LOADER_H_
