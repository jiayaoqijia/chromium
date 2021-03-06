// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>
#include <string>

#include "base/shared_memory.h"
#include "chrome/common/gpu_info.h"
#include "chrome/common/gpu_video_common.h"
#include "ipc/ipc_message_macros.h"

#define IPC_MESSAGE_START GpuMsgStart

namespace gfx {
class Size;
}

namespace IPC {
struct ChannelHandle;
}

struct GPUCreateCommandBufferConfig;
class GPUInfo;

//------------------------------------------------------------------------------
// GPU Messages
// These are messages from the browser to the GPU process.

// Tells the GPU process to initialize itself. The browser explicitly
// requests this be done so that we are guaranteed that the channel is set
// up between the browser and GPU process before doing any work that might
// potentially crash the GPU process. Detection of the child process
// exiting abruptly is predicated on having the IPC channel set up.
IPC_MESSAGE_CONTROL0(GpuMsg_Initialize)

// Tells the GPU process to create a new channel for communication with a
// given renderer.  The channel name is returned in a
// GpuHostMsg_ChannelEstablished message.  The renderer ID is passed so that
// the GPU process reuses an existing channel to that process if it exists.
// This ID is a unique opaque identifier generated by the browser process.
IPC_MESSAGE_CONTROL1(GpuMsg_EstablishChannel,
                     int /* renderer_id */)

// Tells the GPU process to close the channel identified by IPC channel
// handle.  If no channel can be identified, do nothing.
IPC_MESSAGE_CONTROL1(GpuMsg_CloseChannel,
                     IPC::ChannelHandle /* channel_handle */)

// Provides a synchronization point to guarantee that the processing of
// previous asynchronous messages (i.e., GpuMsg_EstablishChannel) has
// completed. (This message can't be synchronous because the
// GpuProcessHost uses an IPC::ChannelProxy, which sends all messages
// asynchronously.) Results in a GpuHostMsg_SynchronizeReply.
IPC_MESSAGE_CONTROL0(GpuMsg_Synchronize)

// Tells the GPU process to create a new command buffer that renders directly
// to a native view. A corresponding GpuCommandBufferStub is created.
IPC_MESSAGE_CONTROL4(GpuMsg_CreateViewCommandBuffer,
                     gfx::PluginWindowHandle, /* view */
                     int32, /* render_view_id */
                     int32, /* renderer_id */
                     GPUCreateCommandBufferConfig /* init_params */)

// Tells the GPU process to create a context for collecting graphics card
// information.
IPC_MESSAGE_CONTROL1(GpuMsg_CollectGraphicsInfo,
                     GPUInfo::Level /* level */)

#if defined(OS_MACOSX)
// Tells the GPU process that the browser process handled the swap
// buffers request with the given number. Note that it is possible
// for the browser process to coalesce frames; it is not guaranteed
// that every GpuHostMsg_AcceleratedSurfaceBuffersSwapped message
// will result in a buffer swap on the browser side.
IPC_MESSAGE_CONTROL3(GpuMsg_AcceleratedSurfaceBuffersSwappedACK,
                     int /* renderer_id */,
                     int32 /* route_id */,
                     uint64 /* swap_buffers_count */)

// Tells the GPU process that the IOSurface of the buffer belonging to
// |renderer_route_id| a given id was destroyed, either by the user closing the
// tab hosting the surface, or by the renderer navigating to a new page.
IPC_MESSAGE_CONTROL2(GpuMsg_DidDestroyAcceleratedSurface,
                     int /* renderer_id */,
                     int32 /* renderer_route_id */)
#endif

// Tells the GPU process to crash.
IPC_MESSAGE_CONTROL0(GpuMsg_Crash)

// Tells the GPU process to hang.
IPC_MESSAGE_CONTROL0(GpuMsg_Hang)

//------------------------------------------------------------------------------
// GPU Host Messages
// These are messages to the browser.

// A renderer sends this when it wants to create a connection to the GPU
// process. The browser will create the GPU process if necessary, and will
// return a handle to the channel via a GpuChannelEstablished message.
IPC_MESSAGE_CONTROL0(GpuHostMsg_EstablishGpuChannel)

// A renderer sends this to the browser process to provide a synchronization
// point for GPU operations, in particular to make sure the GPU channel has
// been established.
IPC_SYNC_MESSAGE_CONTROL0_0(GpuHostMsg_SynchronizeGpu)

// A renderer sends this to the browser process when it wants to
// create a GL context associated with the given view_id.
IPC_SYNC_MESSAGE_CONTROL2_1(GpuHostMsg_CreateViewCommandBuffer,
                            int32, /* render_view_id */
                            GPUCreateCommandBufferConfig, /* init_params */
                            int32 /* route_id */)

// Response from GPU to a GpuHostMsg_EstablishChannel message.
IPC_MESSAGE_CONTROL2(GpuHostMsg_ChannelEstablished,
                     IPC::ChannelHandle, /* channel_handle */
                     GPUInfo /* GPU logging stats */)

// Respond from GPU to a GpuMsg_CreateViewCommandBuffer message.
IPC_MESSAGE_CONTROL1(GpuHostMsg_CommandBufferCreated,
                     int32 /* route_id */)

// Request from GPU to free the browser resources associated with the
// command buffer.
IPC_MESSAGE_CONTROL3(GpuHostMsg_DestroyCommandBuffer,
                     gfx::PluginWindowHandle, /* view */
                     int32, /* render_view_id */
                     int32 /* renderer_id */)

// Response from GPU to a GpuMsg_CollectGraphicsInfo.
IPC_MESSAGE_CONTROL1(GpuHostMsg_GraphicsInfoCollected,
                     GPUInfo /* GPU logging stats */)

// Message from GPU to add a GPU log message to the about:gpu page.
IPC_MESSAGE_CONTROL3(GpuHostMsg_OnLogMessage,
                     int /*severity*/,
                     std::string /* header */,
                     std::string /* message */)

// Response from GPU to a GpuMsg_Synchronize message.
IPC_MESSAGE_CONTROL0(GpuHostMsg_SynchronizeReply)

#if defined(OS_LINUX)
// Resize the window that is being drawn into. It's important that this
// resize be synchronized with the swapping of the front and back buffers.
IPC_SYNC_MESSAGE_CONTROL2_1(GpuHostMsg_ResizeXID,
                            unsigned long, /* xid */
                            gfx::Size, /* size */
                            bool /* success */)
#elif defined(OS_MACOSX)
// This message, used on Mac OS X 10.6 and later (where IOSurface is
// supported), is sent from the GPU process to the browser to indicate that a
// new backing store was allocated for the given "window" (fake
// PluginWindowHandle). The renderer ID and render view ID are needed in
// order to uniquely identify the RenderWidgetHostView on the browser side.
IPC_MESSAGE_CONTROL1(GpuHostMsg_AcceleratedSurfaceSetIOSurface,
                     GpuHostMsg_AcceleratedSurfaceSetIOSurface_Params)

// This message notifies the browser process that the renderer
// swapped the buffers associated with the given "window", which
// should cause the browser to redraw the compositor's contents.
IPC_MESSAGE_CONTROL1(GpuHostMsg_AcceleratedSurfaceBuffersSwapped,
                     GpuHostMsg_AcceleratedSurfaceBuffersSwapped_Params)
#elif defined(OS_WIN)
IPC_MESSAGE_CONTROL2(GpuHostMsg_ScheduleComposite,
                     int32, /* renderer_id */
                     int32 /* render_view_id */)
#endif

//------------------------------------------------------------------------------
// GPU Channel Messages
// These are messages from a renderer process to the GPU process.

// Tells the GPU process to create a new command buffer that renders to an
// offscreen frame buffer. If parent_route_id is not zero, the texture backing
// the frame buffer is mapped into the corresponding parent command buffer's
// namespace, with the name of parent_texture_id. This ID is in the parent's
// namespace.
IPC_SYNC_MESSAGE_CONTROL4_1(GpuChannelMsg_CreateOffscreenCommandBuffer,
                            int32, /* parent_route_id */
                            gfx::Size, /* size */
                            GPUCreateCommandBufferConfig, /* init_params */
                            uint32, /* parent_texture_id */
                            int32 /* route_id */)

// The CommandBufferProxy sends this to the GpuCommandBufferStub in its
// destructor, so that the stub deletes the actual CommandBufferService
// object that it's hosting.
// TODO(apatrick): Implement this.
IPC_SYNC_MESSAGE_CONTROL1_0(GpuChannelMsg_DestroyCommandBuffer,
                            int32 /* instance_id */)

// Create hardware video decoder && associate it with the output |decoder_id|;
// We need this to be control message because we had to map the GpuChannel and
// |decoder_id|.
IPC_MESSAGE_CONTROL2(GpuChannelMsg_CreateVideoDecoder,
                     int32, /* context_route_id */
                     int32) /* decoder_id */

// Release all resource of the hardware video decoder which was assocaited
// with the input |decoder_id|.
// TODO(hclam): This message needs to be asynchronous.
IPC_SYNC_MESSAGE_CONTROL1_0(GpuChannelMsg_DestroyVideoDecoder,
                            int32 /* decoder_id */)

//------------------------------------------------------------------------------
// GPU Command Buffer Messages
// These are messages between a renderer process to the GPU process relating to
// a single OpenGL context.
// Initialize a command buffer with the given number of command entries.
// Returns the shared memory handle for the command buffer mapped to the
// calling process.
IPC_SYNC_MESSAGE_ROUTED1_1(GpuCommandBufferMsg_Initialize,
                           int32 /* size */,
                           base::SharedMemoryHandle /* ring_buffer */)

// Get the current state of the command buffer.
IPC_SYNC_MESSAGE_ROUTED0_1(GpuCommandBufferMsg_GetState,
                           gpu::CommandBuffer::State /* state */)

// Get the current state of the command buffer asynchronously. State is
// returned via UpdateState message.
IPC_MESSAGE_ROUTED0(GpuCommandBufferMsg_AsyncGetState)

// Synchronize the put and get offsets of both processes. Caller passes its
// current put offset. Current state (including get offset) is returned.
IPC_SYNC_MESSAGE_ROUTED1_1(GpuCommandBufferMsg_Flush,
                           int32 /* put_offset */,
                           gpu::CommandBuffer::State /* state */)

// Asynchronously synchronize the put and get offsets of both processes.
// Caller passes its current put offset. Current state (including get offset)
// is returned via an UpdateState message.
IPC_MESSAGE_ROUTED1(GpuCommandBufferMsg_AsyncFlush,
                    int32 /* put_offset */)

// Return the current state of the command buffer following a request via
// an AsyncGetState or AsyncFlush message. (This message is sent from the
// GPU process to the renderer process.)
IPC_MESSAGE_ROUTED1(GpuCommandBufferMsg_UpdateState,
                    gpu::CommandBuffer::State /* state */)

// Indicates that a SwapBuffers call has been issued.
IPC_MESSAGE_ROUTED0(GpuCommandBufferMsg_SwapBuffers)

// Create a shared memory transfer buffer. Returns an id that can be used to
// identify the transfer buffer from a comment.
IPC_SYNC_MESSAGE_ROUTED1_1(GpuCommandBufferMsg_CreateTransferBuffer,
                           int32 /* size */,
                           int32 /* id */)

// Destroy a previously created transfer buffer.
IPC_SYNC_MESSAGE_ROUTED1_0(GpuCommandBufferMsg_DestroyTransferBuffer,
                           int32 /* id */)

// Get the shared memory handle for a transfer buffer mapped to the callers
// process.
IPC_SYNC_MESSAGE_ROUTED1_2(GpuCommandBufferMsg_GetTransferBuffer,
                           int32 /* id */,
                           base::SharedMemoryHandle /* transfer_buffer */,
                           uint32 /* size */)

// Send from command buffer stub to proxy when window is invalid and must be
// repainted.
IPC_MESSAGE_ROUTED0(GpuCommandBufferMsg_NotifyRepaint)

// Tells the GPU process to resize an offscreen frame buffer.
IPC_MESSAGE_ROUTED1(GpuCommandBufferMsg_ResizeOffscreenFrameBuffer,
                    gfx::Size /* size */)

#if defined(OS_MACOSX)
// On Mac OS X the GPU plugin must be offscreen, because there is no
// true cross-process window hierarchy. For this reason we must send
// resize events explicitly to the command buffer stub so it can
// reallocate its backing store and send the new one back to the
// browser. This message is currently used only on 10.6 and later.
IPC_MESSAGE_ROUTED1(GpuCommandBufferMsg_SetWindowSize,
                    gfx::Size /* size */)
#endif

//------------------------------------------------------------------------------
// GPU Video Decoder Messages
// These messages are sent from Renderer process to GPU process.
// Initialize and configure GpuVideoDecoder asynchronously.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderMsg_Initialize,
                    GpuVideoDecoderInitParam)

// Destroy and release GpuVideoDecoder asynchronously.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderMsg_Destroy)

// Start decoder flushing operation.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderMsg_Flush)

// Tell the decoder to start prerolling.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderMsg_Preroll)

// Send input buffer to GpuVideoDecoder.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderMsg_EmptyThisBuffer,
                    GpuVideoDecoderInputBufferParam)

// Ask the GPU process to produce a video frame with the ID.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderMsg_ProduceVideoFrame,
                    int32) /* Video Frame ID */

// Sent from Renderer process to the GPU process to notify that textures are
// generated for a video frame.
IPC_MESSAGE_ROUTED2(GpuVideoDecoderMsg_VideoFrameAllocated,
                    int32, /* Video Frame ID */
                    std::vector<uint32>) /* Textures for video frame */

//------------------------------------------------------------------------------
// GPU Video Decoder Host Messages
// These messages are sent from GPU process to Renderer process.
// Inform GpuVideoDecoderHost that a GpuVideoDecoder is created.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderHostMsg_CreateVideoDecoderDone,
                    int32) /* decoder_id */

// Confirm GpuVideoDecoder had been initialized or failed to initialize.
// TODO(hclam): Change this to Done instead of ACK.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderHostMsg_InitializeACK,
                    GpuVideoDecoderInitDoneParam)

// Confrim GpuVideoDecoder had been destroyed properly.
// TODO(hclam): Change this to Done instead of ACK.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderHostMsg_DestroyACK)

// Confirm decoder had been flushed.
// TODO(hclam): Change this to Done instead of ACK.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderHostMsg_FlushACK)

// Confirm preroll operation is done.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderHostMsg_PrerollDone)

// GpuVideoDecoder has consumed input buffer from transfer buffer.
// TODO(hclam): Change this to Done instead of ACK.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderHostMsg_EmptyThisBufferACK)

// GpuVideoDecoder require new input buffer.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderHostMsg_EmptyThisBufferDone)

// GpuVideoDecoder reports that a video frame is ready to be consumed.
IPC_MESSAGE_ROUTED4(GpuVideoDecoderHostMsg_ConsumeVideoFrame,
                    int32, /* Video Frame ID */
                    int64, /* Timestamp in microseconds */
                    int64, /* Duration in microseconds */
                    int32) /* Flags */

// Allocate video frames for output of the hardware video decoder.
IPC_MESSAGE_ROUTED4(GpuVideoDecoderHostMsg_AllocateVideoFrames,
                    int32,  /* Number of video frames to generate */
                    uint32, /* Width of the video frame */
                    uint32, /* Height of the video frame */
                    int32   /* Format of the video frame */)

// Release all video frames allocated for a hardware video decoder.
IPC_MESSAGE_ROUTED0(GpuVideoDecoderHostMsg_ReleaseAllVideoFrames)

// GpuVideoDecoder report output format change.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderHostMsg_MediaFormatChange,
                    GpuVideoDecoderFormatChangeParam)

// GpuVideoDecoder report error.
IPC_MESSAGE_ROUTED1(GpuVideoDecoderHostMsg_ErrorNotification,
                    GpuVideoDecoderErrorInfoParam)
