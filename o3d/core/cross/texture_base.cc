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


// This file contains the definition of the Texture class.

#include "core/cross/texture_base.h"

#include "core/cross/bitmap.h"
#include "core/cross/pack.h"
#include "core/cross/renderer.h"

namespace o3d {

O3D_DEFN_CLASS(Texture, ParamObject);
O3D_DEFN_CLASS(ParamTexture, RefParamBase);

const char* Texture::kLevelsParamName =
    O3D_STRING_CONSTANT("levels");

Texture::Texture(ServiceLocator* service_locator,
                 Format format,
                 int levels,
                 bool enable_render_surfaces)
    : ParamObject(service_locator),
      renderer_(service_locator->GetService<Renderer>()),
      alpha_is_one_(false),
      format_(format),
      weak_pointer_manager_(this),
      render_surfaces_enabled_(enable_render_surfaces),
      has_unrendered_update_(false),
      last_render_frame_count_(0),
      update_count_(0),
      render_count_(0) {
  RegisterReadOnlyParamRef(kLevelsParamName, &levels_param_);
  levels_param_->set_read_only_value(levels);
}

void Texture::TextureUpdated() {
  CheckLastTextureUpdateRendered();
  last_render_frame_count_ = renderer_->render_frame_count();
  update_count_++;
  has_unrendered_update_ = true;
}

void Texture::CheckLastTextureUpdateRendered() {
  if (has_unrendered_update_ && 
      renderer_->render_frame_count() != last_render_frame_count_) {
    // Then a new frame has been rendered to the screen since we last
    // updated this texture, so that update has been rendered to the screen.
    render_count_++;
    has_unrendered_update_ = false;
  }
}

ObjectBase::Ref ParamTexture::Create(ServiceLocator* service_locator) {
  return ObjectBase::Ref(new ParamTexture(service_locator, false, false));
}

}  // namespace o3d
