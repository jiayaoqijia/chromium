// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/gpu_process_host_ui_shim.h"

#include "chrome/browser/browser_thread.h"
#include "chrome/browser/gpu_process_host.h"
#include "chrome/browser/renderer_host/render_process_host.h"
#include "chrome/browser/renderer_host/render_view_host.h"
#include "chrome/browser/renderer_host/render_widget_host_view.h"
#include "chrome/common/child_process_logging.h"
#include "chrome/common/gpu_messages.h"

#if defined(OS_LINUX)
// These two #includes need to come after gpu_messages.h.
#include <gdk/gdkwindow.h>  // NOLINT
#include <gdk/gdkx.h>  // NOLINT
#include "ui/base/x/x11_util.h"
#include "ui/gfx/gtk_native_view_id_manager.h"
#include "ui/gfx/size.h"
#endif  // defined(OS_LINUX)

// Tasks used by this file
namespace {

class SendOnIOThreadTask : public Task {
 public:
  explicit SendOnIOThreadTask(IPC::Message* msg) : msg_(msg) {
  }

 private:
  void Run() {
    GpuProcessHost::Get()->Send(msg_);
  }
  IPC::Message* msg_;
};

}  // namespace

GpuProcessHostUIShim::GpuProcessHostUIShim() : last_routing_id_(1) {
}

GpuProcessHostUIShim::~GpuProcessHostUIShim() {
}

// static
GpuProcessHostUIShim* GpuProcessHostUIShim::GetInstance() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
  return Singleton<GpuProcessHostUIShim>::get();
}

bool GpuProcessHostUIShim::Send(IPC::Message* msg) {
  DCHECK(CalledOnValidThread());
  BrowserThread::PostTask(BrowserThread::IO,
                          FROM_HERE,
                          new SendOnIOThreadTask(msg));
  return true;
}

int32 GpuProcessHostUIShim::GetNextRoutingId() {
  DCHECK(CalledOnValidThread());
  return ++last_routing_id_;
}

void GpuProcessHostUIShim::AddRoute(int32 routing_id,
                                    IPC::Channel::Listener* listener) {
  DCHECK(CalledOnValidThread());
  router_.AddRoute(routing_id, listener);
}

void GpuProcessHostUIShim::RemoveRoute(int32 routing_id) {
  DCHECK(CalledOnValidThread());
  router_.RemoveRoute(routing_id);
}

bool GpuProcessHostUIShim::OnMessageReceived(const IPC::Message& message) {
  DCHECK(CalledOnValidThread());

  if (message.routing_id() == MSG_ROUTING_CONTROL)
    return OnControlMessageReceived(message);

  return router_.RouteMessage(message);
}

void GpuProcessHostUIShim::CollectGraphicsInfoAsynchronously(
    GPUInfo::Level level) {
  DCHECK(CalledOnValidThread());
  BrowserThread::PostTask(
      BrowserThread::IO,
      FROM_HERE,
      new SendOnIOThreadTask(new GpuMsg_CollectGraphicsInfo(level)));
}

void GpuProcessHostUIShim::SendAboutGpuCrash() {
  DCHECK(CalledOnValidThread());
  BrowserThread::PostTask(
      BrowserThread::IO,
      FROM_HERE,
      new SendOnIOThreadTask(new GpuMsg_Crash()));
}

void GpuProcessHostUIShim::SendAboutGpuHang() {
  DCHECK(CalledOnValidThread());
  BrowserThread::PostTask(
      BrowserThread::IO,
      FROM_HERE,
      new SendOnIOThreadTask(new GpuMsg_Hang()));
}

const GPUInfo& GpuProcessHostUIShim::gpu_info() const {
  DCHECK(CalledOnValidThread());
  return gpu_info_;
}

void GpuProcessHostUIShim::OnDestroyCommandBuffer(
    gfx::PluginWindowHandle window, int32 renderer_id,
    int32 render_view_id) {
  if (!window)
    return;

#if defined(OS_LINUX)
  GtkNativeViewManager* manager = GtkNativeViewManager::GetInstance();
  manager->ReleasePermanentXID(window);
#elif defined(OS_MACOSX) || defined(OS_WIN)
  RenderProcessHost* process = RenderProcessHost::FromID(renderer_id);
  RenderWidgetHost* host = NULL;
  if (process) {
    host = static_cast<RenderWidgetHost*>(
        process->GetListenerByID(render_view_id));
  }
  RenderWidgetHostView* view = NULL;
  if (host)
    view = host->view();

  if (view) {
#if defined(OS_MACOSX)
    view->DestroyFakePluginWindowHandle(window);
#elif defined(OS_WIN)
    view->ShowCompositorHostWindow(false);
#endif
  }
#endif  // defined(OS_MACOSX) || defined(OS_WIN)
}

void GpuProcessHostUIShim::OnGraphicsInfoCollected(const GPUInfo& gpu_info) {
  gpu_info_ = gpu_info;
  child_process_logging::SetGpuInfo(gpu_info);

  // Used only in testing.
  if (gpu_info_collected_callback_.get())
    gpu_info_collected_callback_->Run();
}

void GpuProcessHostUIShim::OnLogMessage(int level,
    const std::string& header,
    const std::string& message) {
  DictionaryValue* dict = new DictionaryValue();
  dict->SetInteger("level", level);
  dict->SetString("header", header);
  dict->SetString("message", message);
  log_messages_.Append(dict);
}

bool GpuProcessHostUIShim::OnControlMessageReceived(
    const IPC::Message& message) {
  DCHECK(CalledOnValidThread());

  IPC_BEGIN_MESSAGE_MAP(GpuProcessHostUIShim, message)
    IPC_MESSAGE_HANDLER(GpuHostMsg_DestroyCommandBuffer,
                        OnDestroyCommandBuffer)
    IPC_MESSAGE_HANDLER(GpuHostMsg_GraphicsInfoCollected,
                        OnGraphicsInfoCollected)
    IPC_MESSAGE_HANDLER(GpuHostMsg_OnLogMessage,
                        OnLogMessage)
#if defined(OS_LINUX)
    IPC_MESSAGE_HANDLER_DELAY_REPLY(GpuHostMsg_ResizeXID, OnResizeXID)
#elif defined(OS_MACOSX)
    IPC_MESSAGE_HANDLER(GpuHostMsg_AcceleratedSurfaceSetIOSurface,
                        OnAcceleratedSurfaceSetIOSurface)
    IPC_MESSAGE_HANDLER(GpuHostMsg_AcceleratedSurfaceBuffersSwapped,
                        OnAcceleratedSurfaceBuffersSwapped)
#elif defined(OS_WIN)
    IPC_MESSAGE_HANDLER(GpuHostMsg_ScheduleComposite, OnScheduleComposite);
#endif
    IPC_MESSAGE_UNHANDLED_ERROR()
  IPC_END_MESSAGE_MAP()

  return true;
}

namespace {

void SendDelayedReply(IPC::Message* reply_msg) {
    BrowserThread::PostTask(
        BrowserThread::IO,
        FROM_HERE,
        new SendOnIOThreadTask(reply_msg));
}

}  // namespace

#if defined(OS_LINUX)

void GpuProcessHostUIShim::OnResizeXID(unsigned long xid, gfx::Size size,
                                       IPC::Message *reply_msg) {
  GdkWindow* window = reinterpret_cast<GdkWindow*>(gdk_xid_table_lookup(xid));
  if (window) {
    Display* display = GDK_WINDOW_XDISPLAY(window);
    gdk_window_resize(window, size.width(), size.height());
    XSync(display, False);
  }

  GpuHostMsg_ResizeXID::WriteReplyParams(reply_msg, (window != NULL));
  SendDelayedReply(reply_msg);
}

#elif defined(OS_MACOSX)

void GpuProcessHostUIShim::OnAcceleratedSurfaceSetIOSurface(
    const GpuHostMsg_AcceleratedSurfaceSetIOSurface_Params& params) {
  RenderViewHost* host = RenderViewHost::FromID(params.renderer_id,
                                                params.render_view_id);
  if (!host)
    return;
  RenderWidgetHostView* view = host->view();
  if (!view)
    return;
  view->AcceleratedSurfaceSetIOSurface(params.window,
                                       params.width,
                                       params.height,
                                       params.identifier);
}

void GpuProcessHostUIShim::OnAcceleratedSurfaceBuffersSwapped(
    const GpuHostMsg_AcceleratedSurfaceBuffersSwapped_Params& params) {
  RenderViewHost* host = RenderViewHost::FromID(params.renderer_id,
                                                params.render_view_id);
  if (!host)
    return;
  RenderWidgetHostView* view = host->view();
  if (!view)
    return;
  view->AcceleratedSurfaceBuffersSwapped(
      // Parameters needed to swap the IOSurface.
      params.window,
      params.surface_id,
      // Parameters needed to formulate an acknowledgment.
      params.renderer_id,
      params.route_id,
      params.swap_buffers_count);
}

#elif defined(OS_WIN)

void GpuProcessHostUIShim::OnScheduleComposite(int renderer_id,
    int render_view_id) {
  RenderViewHost* host = RenderViewHost::FromID(renderer_id,
                                                render_view_id);
  if (!host) {
    return;
  }
  host->ScheduleComposite();
}

#endif
