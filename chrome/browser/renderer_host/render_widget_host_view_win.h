// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_RENDERER_HOST_RENDER_WIDGET_HOST_VIEW_WIN_H_
#define CHROME_BROWSER_RENDERER_HOST_RENDER_WIDGET_HOST_VIEW_WIN_H_
#pragma once

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlmisc.h>

#include <vector>

#include "base/scoped_comptr_win.h"
#include "base/scoped_ptr.h"
#include "base/scoped_vector.h"
#include "base/task.h"
#include "chrome/browser/accessibility/browser_accessibility_manager.h"
#include "chrome/browser/ime_input.h"
#include "chrome/browser/renderer_host/render_widget_host_view.h"
#include "chrome/common/notification_observer.h"
#include "chrome/common/notification_registrar.h"
#include "ui/gfx/native_widget_types.h"
#include "webkit/glue/webcursor.h"

class BackingStore;
class RenderWidgetHost;

namespace gfx {
class Size;
class Rect;
}

namespace IPC {
class Message;
}

namespace ui {
class ViewProp;
}

typedef CWinTraits<WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0>
    RenderWidgetHostHWNDTraits;

extern const wchar_t kRenderWidgetHostHWNDClass[];

///////////////////////////////////////////////////////////////////////////////
// RenderWidgetHostViewWin
//
//  An object representing the "View" of a rendered web page. This object is
//  responsible for displaying the content of the web page, receiving windows
//  messages, and containing plugins HWNDs. It is the implementation of the
//  RenderWidgetHostView that the cross-platform RenderWidgetHost object uses
//  to display the data.
//
//  Comment excerpted from render_widget_host.h:
//
//    "The lifetime of the RenderWidgetHostHWND is tied to the render process.
//     If the render process dies, the RenderWidgetHostHWND goes away and all
//     references to it must become NULL."
//
class RenderWidgetHostViewWin
    : public CWindowImpl<RenderWidgetHostViewWin,
                         CWindow,
                         RenderWidgetHostHWNDTraits>,
      public RenderWidgetHostView,
      public NotificationObserver,
      public BrowserAccessibilityDelegate {
 public:
  // The view will associate itself with the given widget.
  explicit RenderWidgetHostViewWin(RenderWidgetHost* widget);
  virtual ~RenderWidgetHostViewWin();

  void CreateWnd(HWND parent);

  DECLARE_WND_CLASS_EX(kRenderWidgetHostHWNDClass, CS_DBLCLKS, 0);

  BEGIN_MSG_MAP(RenderWidgetHostHWND)
    MSG_WM_CREATE(OnCreate)
    MSG_WM_ACTIVATE(OnActivate)
    MSG_WM_DESTROY(OnDestroy)
    MSG_WM_PAINT(OnPaint)
    MSG_WM_NCPAINT(OnNCPaint)
    MSG_WM_ERASEBKGND(OnEraseBkgnd)
    MSG_WM_SETCURSOR(OnSetCursor)
    MSG_WM_SETFOCUS(OnSetFocus)
    MSG_WM_KILLFOCUS(OnKillFocus)
    MSG_WM_CAPTURECHANGED(OnCaptureChanged)
    MSG_WM_CANCELMODE(OnCancelMode)
    MSG_WM_INPUTLANGCHANGE(OnInputLangChange)
    MSG_WM_THEMECHANGED(OnThemeChanged)
    MSG_WM_NOTIFY(OnNotify)
    MESSAGE_HANDLER(WM_IME_SETCONTEXT, OnImeSetContext)
    MESSAGE_HANDLER(WM_IME_STARTCOMPOSITION, OnImeStartComposition)
    MESSAGE_HANDLER(WM_IME_COMPOSITION, OnImeComposition)
    MESSAGE_HANDLER(WM_IME_ENDCOMPOSITION, OnImeEndComposition)
    MESSAGE_HANDLER(WM_MOUSEMOVE, OnMouseEvent)
    MESSAGE_HANDLER(WM_MOUSELEAVE, OnMouseEvent)
    MESSAGE_HANDLER(WM_LBUTTONDOWN, OnMouseEvent)
    MESSAGE_HANDLER(WM_MBUTTONDOWN, OnMouseEvent)
    MESSAGE_HANDLER(WM_RBUTTONDOWN, OnMouseEvent)
    MESSAGE_HANDLER(WM_LBUTTONUP, OnMouseEvent)
    MESSAGE_HANDLER(WM_MBUTTONUP, OnMouseEvent)
    MESSAGE_HANDLER(WM_RBUTTONUP, OnMouseEvent)
    MESSAGE_HANDLER(WM_LBUTTONDBLCLK, OnMouseEvent)
    MESSAGE_HANDLER(WM_MBUTTONDBLCLK, OnMouseEvent)
    MESSAGE_HANDLER(WM_RBUTTONDBLCLK, OnMouseEvent)
    MESSAGE_HANDLER(WM_SYSKEYDOWN, OnKeyEvent)
    MESSAGE_HANDLER(WM_SYSKEYUP, OnKeyEvent)
    MESSAGE_HANDLER(WM_KEYDOWN, OnKeyEvent)
    MESSAGE_HANDLER(WM_KEYUP, OnKeyEvent)
    MESSAGE_HANDLER(WM_MOUSEWHEEL, OnWheelEvent)
    MESSAGE_HANDLER(WM_MOUSEHWHEEL, OnWheelEvent)
    MESSAGE_HANDLER(WM_HSCROLL, OnWheelEvent)
    MESSAGE_HANDLER(WM_VSCROLL, OnWheelEvent)
    MESSAGE_HANDLER(WM_CHAR, OnKeyEvent)
    MESSAGE_HANDLER(WM_SYSCHAR, OnKeyEvent)
    MESSAGE_HANDLER(WM_IME_CHAR, OnKeyEvent)
    MESSAGE_HANDLER(WM_MOUSEACTIVATE, OnMouseActivate)
    MESSAGE_HANDLER(WM_GETOBJECT, OnGetObject)
  END_MSG_MAP()

  // Implementation of RenderWidgetHostView:
  virtual void InitAsPopup(RenderWidgetHostView* parent_host_view,
                           const gfx::Rect& pos);
  virtual void InitAsFullscreen(RenderWidgetHostView* parent_host_view);
  virtual RenderWidgetHost* GetRenderWidgetHost() const;
  virtual void DidBecomeSelected();
  virtual void WasHidden();
  virtual void SetSize(const gfx::Size& size);
  virtual gfx::NativeView GetNativeView();
  virtual void MovePluginWindows(
      const std::vector<webkit::npapi::WebPluginGeometry>& moves);
  virtual void Focus();
  virtual void Blur();
  virtual bool HasFocus();
  virtual void Show();
  virtual void Hide();
  virtual bool IsShowing();
  virtual gfx::Rect GetViewBounds() const;
  virtual void UpdateCursor(const WebCursor& cursor);
  virtual void SetIsLoading(bool is_loading);
  virtual void ImeUpdateTextInputState(WebKit::WebTextInputType type,
                                       const gfx::Rect& caret_rect);
  virtual void ImeCancelComposition();
  virtual void DidUpdateBackingStore(
      const gfx::Rect& scroll_rect, int scroll_dx, int scroll_dy,
      const std::vector<gfx::Rect>& copy_rects);
  virtual void RenderViewGone(base::TerminationStatus status,
                              int error_code);
  virtual void WillWmDestroy();  // called by TabContents before DestroyWindow
  virtual void WillDestroyRenderWidget(RenderWidgetHost* rwh);
  virtual void Destroy();
  virtual void SetTooltipText(const std::wstring& tooltip_text);
  virtual BackingStore* AllocBackingStore(const gfx::Size& size);
  virtual void SetBackground(const SkBitmap& background);
  virtual bool ContainsNativeView(gfx::NativeView native_view) const;
  virtual void SetVisuallyDeemphasized(const SkColor* color, bool animate);

  virtual gfx::PluginWindowHandle GetCompositorHostWindow();
  virtual void ShowCompositorHostWindow(bool show);

  virtual void OnAccessibilityNotifications(
      const std::vector<ViewHostMsg_AccessibilityNotification_Params>& params);

  // Implementation of NotificationObserver:
  virtual void Observe(NotificationType type,
                       const NotificationSource& source,
                       const NotificationDetails& details);

  // Implementation of BrowserAccessibilityDelegate:
  virtual void SetAccessibilityFocus(int acc_obj_id);
  virtual void AccessibilityDoDefaultAction(int acc_obj_id);

 protected:
  // Windows Message Handlers
  LRESULT OnCreate(CREATESTRUCT* create_struct);
  void OnActivate(UINT, BOOL, HWND);
  void OnDestroy();
  void OnPaint(HDC unused_dc);
  void OnNCPaint(HRGN update_region);
  LRESULT OnEraseBkgnd(HDC dc);
  LRESULT OnSetCursor(HWND window, UINT hittest_code, UINT mouse_message_id);
  void OnSetFocus(HWND window);
  void OnKillFocus(HWND window);
  void OnCaptureChanged(HWND window);
  void OnCancelMode();
  void OnInputLangChange(DWORD character_set, HKL input_language_id);
  void OnThemeChanged();
  LRESULT OnNotify(int w_param, NMHDR* header);
  LRESULT OnImeSetContext(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnImeStartComposition(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnImeComposition(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnImeEndComposition(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnMouseEvent(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnKeyEvent(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnWheelEvent(
      UINT message, WPARAM wparam, LPARAM lparam, BOOL& handled);
  LRESULT OnMouseActivate(UINT message,
                          WPARAM wparam,
                          LPARAM lparam,
                          BOOL& handled);
  // Handle MSAA requests for accessibility information.
  LRESULT OnGetObject(UINT message, WPARAM wparam, LPARAM lparam,
                      BOOL& handled);
  // Handle vertical scrolling
  LRESULT OnVScroll(int code, short position, HWND scrollbar_control);
  // Handle horizontal scrolling
  LRESULT OnHScroll(int code, short position, HWND scrollbar_control);

  void OnFinalMessage(HWND window);

 private:
  // Updates the display cursor to the current cursor if the cursor is over this
  // render view.
  void UpdateCursorIfOverSelf();

  // Tells Windows that we want to hear about mouse exit messages.
  void TrackMouseLeave(bool start_tracking);

  // Sends a message to the RenderView in the renderer process.
  bool Send(IPC::Message* message);

  // Set the tooltip region to the size of the window, creating the tooltip
  // hwnd if it has not been created yet.
  void EnsureTooltip();

  // Tooltips become invalid when the root ancestor changes. When the View
  // becomes hidden, this method is called to reset the tooltip.
  void ResetTooltip();

  // Sends the specified mouse event to the renderer.
  void ForwardMouseEventToRenderer(UINT message, WPARAM wparam, LPARAM lparam);

  // Synthesize mouse wheel event.
  LRESULT SynthesizeMouseWheel(bool is_vertical, int scroll_code,
                               short scroll_position);

  // Shuts down the render_widget_host_.  This is a separate function so we can
  // invoke it from the message loop.
  void ShutdownHost();

  // Redraws the window synchronously, and any child windows (i.e. plugins)
  // asynchronously.
  void Redraw();

  // Draw our background over the given HDC in the given |rect|. The background
  // will be tiled such that it lines up with existing tiles starting from the
  // origin of |dc|.
  void DrawBackground(const RECT& rect, CPaintDC* dc);

  // Create an intermediate window between the given HWND and its parent.
  HWND ReparentWindow(HWND window);

  // Clean up the compositor window, if needed.
  void CleanupCompositorWindow();

  // Whether the window should be activated.
  bool IsActivatable() const;

  // The associated Model.
  RenderWidgetHost* render_widget_host_;

  // When we are doing accelerated compositing
  HWND compositor_host_window_;

  // The cursor for the page. This is passed up from the renderer.
  WebCursor current_cursor_;

  // Indicates if the page is loading.
  bool is_loading_;

  // true if we are currently tracking WM_MOUSEEXIT messages.
  bool track_mouse_leave_;

  // Wrapper class for IME input.
  // (See "chrome/browser/ime_input.h" for its details.)
  ImeInput ime_input_;

  // Represents whether or not this browser process is receiving status
  // messages about the focused edit control from a renderer process.
  bool ime_notification_;

  // true if Enter was hit when render widget host was in focus.
  bool capture_enter_key_;

  // true if the View is not visible.
  bool is_hidden_;

  // True if we're in the midst of a paint operation and should respond to
  // DidPaintRect() notifications by merely invalidating.  See comments on
  // render_widget_host_view.h:DidPaintRect().
  bool about_to_validate_and_paint_;

  // true if the View should be closed when its HWND is deactivated (used to
  // support SELECT popups which are closed when they are deactivated).
  bool close_on_deactivate_;

  // Whether Destroy() has been called.  Used to detect a crasher
  // (http://crbug.com/24248) where render_view_host_ has been deleted when
  // OnFinalMessage is called.
  bool being_destroyed_;

  // Tooltips
  // The text to be shown in the tooltip, supplied by the renderer.
  std::wstring tooltip_text_;
  // The tooltip control hwnd
  HWND tooltip_hwnd_;
  // Whether or not a tooltip is currently visible. We use this to track
  // whether or not we want to force-close the tooltip when we receive mouse
  // move notifications from the renderer. See comment in OnMsgSetTooltipText.
  bool tooltip_showing_;

  // Factory used to safely scope delayed calls to ShutdownHost().
  ScopedRunnableMethodFactory<RenderWidgetHostViewWin> shutdown_factory_;

  // Our parent HWND.  We keep a reference to it as we SetParent(NULL) when
  // hidden to prevent getting messages (Paint, Resize...), and we reattach
  // when shown again.
  HWND parent_hwnd_;

  // Instance of accessibility information for the root of the MSAA
  // tree representation of the WebKit render tree.
  scoped_ptr<BrowserAccessibilityManager> browser_accessibility_manager_;

  // The time at which this view started displaying white pixels as a result of
  // not having anything to paint (empty backing store from renderer). This
  // value returns true for is_null() if we are not recording whiteout times.
  base::TimeTicks whiteout_start_time_;

  // The time it took after this view was selected for it to be fully painted.
  base::TimeTicks tab_switch_paint_time_;

  // A color we use to shade the entire render view. If 100% transparent, we do
  // not shade the render view.
  SkColor overlay_color_;

  // Registrar so we can listen to RENDERER_PROCESS_TERMINATED events.
  NotificationRegistrar registrar_;

  // Stores the current text input type received by ImeUpdateTextInputState()
  // method.
  WebKit::WebTextInputType text_input_type_;

  ScopedVector<ui::ViewProp> props_;

  scoped_ptr<ui::ViewProp> accessibility_prop_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostViewWin);
};

#endif  // CHROME_BROWSER_RENDERER_HOST_RENDER_WIDGET_HOST_VIEW_WIN_H_
