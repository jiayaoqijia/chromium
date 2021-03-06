/*
 * Copyright 2009, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


// This file contains the ClientInfoManager implementation

#include "core/cross/client_info.h"
#include <vector>
#include "base/string_util.h"
#include "core/cross/types.h"
#include "core/cross/service_dependency.h"
#include "core/cross/object_manager.h"

namespace o3d {

ClientInfo::ClientInfo()
    : num_objects_(0),
      texture_memory_used_(0),
      buffer_memory_used_(0),
      software_renderer_(false),
      non_power_of_two_textures_(false),
      version_(O3D_PLUGIN_VERSION) {
}

const InterfaceId ClientInfoManager::kInterfaceId =
    InterfaceTraits<ClientInfoManager>::kInterfaceId;

ClientInfoManager::ClientInfoManager(ServiceLocator* service_locator)
    : service_(service_locator, this) {
}

const ClientInfo& ClientInfoManager::client_info() {
  ServiceDependency<ObjectManager> object_manager_(service_.service_locator());
  client_info_.num_objects_ = object_manager_->GetNumObjects();
  return client_info_;
}

}  // namespace o3d
