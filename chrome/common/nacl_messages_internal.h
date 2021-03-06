// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process.h"
#include "chrome/common/nacl_types.h"
#include "ipc/ipc_message_macros.h"

#define IPC_MESSAGE_START NaClMsgStart

//-----------------------------------------------------------------------------
// NaClProcess messages
// These are messages sent from the browser to the NaCl process.
// Tells the NaCl process to start.
IPC_MESSAGE_CONTROL1(NaClProcessMsg_Start,
                     std::vector<nacl::FileDescriptor> /* sockets */)

// Tells the NaCl broker to launch a NaCl loader process.
IPC_MESSAGE_CONTROL1(NaClProcessMsg_LaunchLoaderThroughBroker,
                     std::wstring /* channel ID for the loader */)

// Notify the browser process that the loader was launched successfully.
IPC_MESSAGE_CONTROL2(NaClProcessMsg_LoaderLaunched,
                     std::wstring,  /* channel ID for the loader */
                     base::ProcessHandle /* loader process handle */)

// Notify the broker that all loader processes have been terminated and it
// should shutdown.
IPC_MESSAGE_CONTROL0(NaClProcessMsg_StopBroker)
