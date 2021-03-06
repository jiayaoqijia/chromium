// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_TAB_CONTENTS_TAB_CONTENTS_VIEW_H_
#define CHROME_BROWSER_TAB_CONTENTS_TAB_CONTENTS_VIEW_H_
#pragma once

#include <map>
#include <string>

#include "base/basictypes.h"
#include "chrome/browser/renderer_host/render_view_host_delegate.h"
#include "chrome/browser/tab_contents/render_view_host_delegate_helper.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/gfx/rect.h"
#include "ui/gfx/size.h"

class RenderViewHost;
class RenderWidgetHost;
class RenderWidgetHostView;
class TabContents;

// The TabContentsView is an interface that is implemented by the platform-
// dependent web contents views. The TabContents uses this interface to talk to
// them. View-related messages will also get forwarded directly to this class
// from RenderViewHost via RenderViewHostDelegate::View.
//
// It contains a small amount of logic with respect to creating new sub-view
// that should be the same for all platforms.
class TabContentsView : public RenderViewHostDelegate::View {
 public:
  explicit TabContentsView(TabContents* tab_contents);
  virtual ~TabContentsView();

  // Creates the appropriate type of TabContentsView for the current system.
  // The return value is a new heap allocated view with ownership passing to
  // the caller.
  static TabContentsView* Create(TabContents* tab_contents);

  TabContents* tab_contents() const { return tab_contents_; }

  virtual void CreateView(const gfx::Size& initial_size) = 0;

  // Sets up the View that holds the rendered web page, receives messages for
  // it and contains page plugins. The host view should be sized to the current
  // size of the TabContents.
  virtual RenderWidgetHostView* CreateViewForWidget(
      RenderWidgetHost* render_widget_host) = 0;

  // Returns the native widget that contains the contents of the tab.
  virtual gfx::NativeView GetNativeView() const = 0;

  // Returns the native widget with the main content of the tab (i.e. the main
  // render view host, though there may be many popups in the tab as children of
  // the container).
  virtual gfx::NativeView GetContentNativeView() const = 0;

  // Returns the outermost native view. This will be used as the parent for
  // dialog boxes.
  virtual gfx::NativeWindow GetTopLevelNativeWindow() const = 0;

  // Computes the rectangle for the native widget that contains the contents of
  // the tab relative to its parent.
  virtual void GetContainerBounds(gfx::Rect *out) const = 0;

  // Helper function for GetContainerBounds. Most callers just want to know the
  // size, and this makes it more clear.
  gfx::Size GetContainerSize() const {
    gfx::Rect rc;
    GetContainerBounds(&rc);
    return gfx::Size(rc.width(), rc.height());
  }

  // Sets the page title for the native widgets corresponding to the view. This
  // is not strictly necessary and isn't expected to be displayed anywhere, but
  // can aid certain debugging tools such as Spy++ on Windows where you are
  // trying to find a specific window.
  virtual void SetPageTitle(const std::wstring& title) = 0;

  // Used to notify the view that a tab has crashed so each platform can
  // prepare the sad tab.
  virtual void OnTabCrashed(base::TerminationStatus status,
                            int error_code) = 0;

  // TODO(brettw) this is a hack. It's used in two places at the time of this
  // writing: (1) when render view hosts switch, we need to size the replaced
  // one to be correct, since it wouldn't have known about sizes that happened
  // while it was hidden; (2) in constrained windows.
  //
  // (1) will be fixed once interstitials are cleaned up. (2) seems like it
  // should be cleaned up or done some other way, since this works for normal
  // TabContents without the special code.
  virtual void SizeContents(const gfx::Size& size) = 0;

  // Invoked from the platform dependent web contents view when a
  // RenderWidgetHost is deleted. Removes |host| from internal maps.
  void RenderWidgetHostDestroyed(RenderWidgetHost* host);

  // Invoked when the TabContents is notified that the RenderView has been
  // fully created. The default implementation does nothing; override
  // for platform-specific behavior is needed.
  virtual void RenderViewCreated(RenderViewHost* host);

  // Sets focus to the native widget for this tab.
  virtual void Focus() = 0;

  // Sets focus to the appropriate element when the tab contents is shown the
  // first time.
  virtual void SetInitialFocus() = 0;

  // Stores the currently focused view.
  virtual void StoreFocus() = 0;

  // Restores focus to the last focus view. If StoreFocus has not yet been
  // invoked, SetInitialFocus is invoked.
  virtual void RestoreFocus() = 0;

  // RenderViewHostDelegate::View method. Forwards to the TabContentsDelegate.
  virtual void LostCapture();

  // Keyboard events forwarding from the RenderViewHost.
  // The default implementation just forward the events to the
  // TabContentsDelegate object.
  virtual bool PreHandleKeyboardEvent(const NativeWebKeyboardEvent& event,
                                      bool* is_keyboard_shortcut);

  // Keyboard events forwarding from the RenderViewHost.
  // The default implementation just forward the events to the
  // TabContentsDelegate object.
  virtual void HandleKeyboardEvent(const NativeWebKeyboardEvent& event);

  // Simple mouse event forwarding from the RenderViewHost.
  virtual void HandleMouseMove() {}
  virtual void HandleMouseDown() {}
  virtual void HandleMouseLeave() {}
  virtual void HandleMouseUp();
  virtual void HandleMouseActivate();

  // Notification that the preferred size of the contents has changed.
  virtual void UpdatePreferredSize(const gfx::Size& pref_size);

  // If we try to close the tab while a drag is in progress, we crash.  These
  // methods allow the tab contents to determine if a drag is in progress and
  // postpone the tab closing.
  virtual bool IsDoingDrag() const;
  virtual void CancelDragAndCloseTab() {}

  // If we close the tab while a UI control is in an event-tracking
  // loop, the control may message freed objects and crash.
  // TabContents::Close() calls IsEventTracking(), and if it returns
  // true CloseTabAfterEventTracking() is called and the close is not
  // completed.
  virtual bool IsEventTracking() const;
  virtual void CloseTabAfterEventTracking() {}

  // Get the bounds of the View, relative to the parent.
  virtual void GetViewBounds(gfx::Rect* out) const = 0;

 protected:
  TabContentsView();  // Abstract interface.

  // Internal functions used to support the CreateNewWidget() method. If a
  // platform requires plugging into widget creation at a lower level then a
  // subclass might want to override these functions, but otherwise they should
  // be fine just implementing RenderWidgetHostView::InitAsPopup().
  //
  // The Create function returns the newly created widget so it can be
  // associated with the given route. When the widget needs to be shown later,
  // we'll look it up again and pass the object to the Show functions rather
  // than the route ID.
  virtual RenderWidgetHostView* CreateNewWidgetInternal(
      int route_id,
      WebKit::WebPopupType popup_type);
  virtual void ShowCreatedWidgetInternal(RenderWidgetHostView* widget_host_view,
                                         const gfx::Rect& initial_pos);
  virtual void ShowCreatedFullscreenWidgetInternal(
      RenderWidgetHostView* widget_host_view);
  virtual RenderWidgetHostView* CreateNewFullscreenWidgetInternal(
      int route_id,
      WebKit::WebPopupType popup_type);

  // Common implementations of some RenderViewHostDelegate::View methods.
  RenderViewHostDelegateViewHelper delegate_view_helper_;

 private:
  // We implement these functions on RenderViewHostDelegate::View directly and
  // do some book-keeping associated with the request. The request is then
  // forwarded to *Internal which does platform-specific work.
  virtual void CreateNewWindow(
      int route_id,
      const ViewHostMsg_CreateWindow_Params& params);
  virtual void CreateNewWidget(int route_id, WebKit::WebPopupType popup_type);
  virtual void CreateNewFullscreenWidget(
      int route_id, WebKit::WebPopupType popup_type);
  virtual void ShowCreatedWindow(int route_id,
                                 WindowOpenDisposition disposition,
                                 const gfx::Rect& initial_pos,
                                 bool user_gesture);
  virtual void ShowCreatedWidget(int route_id, const gfx::Rect& initial_pos);
  virtual void Activate();
  virtual void Deactivate();
  virtual void ShowCreatedFullscreenWidget(int route_id);

  // The TabContents whose contents we display.
  TabContents* tab_contents_;

  // Tracks created TabContents objects that have not been shown yet. They are
  // identified by the route ID passed to CreateNewWindow.
  typedef std::map<int, TabContents*> PendingContents;
  PendingContents pending_contents_;

  // These maps hold on to the widgets that we created on behalf of the
  // renderer that haven't shown yet.
  typedef std::map<int, RenderWidgetHostView*> PendingWidgetViews;
  PendingWidgetViews pending_widget_views_;

  DISALLOW_COPY_AND_ASSIGN(TabContentsView);
};

#endif  // CHROME_BROWSER_TAB_CONTENTS_TAB_CONTENTS_VIEW_H_
