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


// This file contains the declaration of functions needed to
// instantiate a renderer from the core cross-platform API so that we
// can use it for serialization of the scene graph on all systems
// without needing graphics.

#ifndef O3D_CONVERTER_CROSS_RENDERER_STUB_H_
#define O3D_CONVERTER_CROSS_RENDERER_STUB_H_

#include "core/cross/renderer.h"

namespace o3d {

// Please see core/cross/renderer.h for documentation of these
// functions.  With the exception of the "Create..." methods, these
// are mostly just stubbed out here, and don't do anything.

class RendererStub : public Renderer {
 public:
  static Renderer* CreateDefault(ServiceLocator* service_locator);
  virtual InitStatus InitPlatformSpecific(const DisplayWindow& display,
                                          bool off_screen);
  virtual void InitCommon();
  virtual void UninitCommon();
  virtual void Destroy();
  virtual void Resize(int width, int height);
  virtual Primitive::Ref CreatePrimitive();
  virtual DrawElement::Ref CreateDrawElement();
  virtual VertexBuffer::Ref CreateVertexBuffer();
  virtual IndexBuffer::Ref CreateIndexBuffer();
  virtual Effect::Ref CreateEffect();
  virtual Sampler::Ref CreateSampler();
  virtual RenderDepthStencilSurface::Ref CreateDepthStencilSurface(int width,
                                                                   int height);
  virtual StreamBank::Ref CreateStreamBank();
  ParamCache *CreatePlatformSpecificParamCache();
  virtual void SetViewportInPixels(int left,
                                   int top,
                                   int width,
                                   int height,
                                   float min_z,
                                   float max_z);
  virtual bool GoFullscreen(const DisplayWindow& display,
                            int mode_id);
  virtual bool CancelFullscreen(const DisplayWindow& display,
                                int width, int height);
  virtual bool fullscreen() const;
  virtual void GetDisplayModes(std::vector<DisplayMode> *modes);
  virtual bool GetDisplayMode(int id, DisplayMode *mode);

  // Overridden from Renderer.
  virtual const int* GetRGBAUByteNSwizzleTable();

 protected:
  explicit RendererStub(ServiceLocator* service_locator);

  // Overridden from Renderer.
  virtual bool PlatformSpecificBeginDraw();

  // Overridden from Renderer.
  virtual void PlatformSpecificEndDraw();

  // Overridden from Renderer.
  virtual bool PlatformSpecificStartRendering();

  // Overridden from Renderer.
  virtual void PlatformSpecificFinishRendering();

  // Overridden from Renderer.
  virtual void PlatformSpecificPresent();

  // Overridden from Renderer.
  virtual void PlatformSpecificClear(const Float4 &color,
                                     bool color_flag,
                                     float depth,
                                     bool depth_flag,
                                     int stencil,
                                     bool stencil_flag);

  // Overridden from Renderer.
  virtual void SetBackBufferPlatformSpecific();

  // Overridden from Renderer.
  virtual void ApplyDirtyStates();

  // Overridden from Renderer.
  virtual void SetRenderSurfacesPlatformSpecific(
      const RenderSurface* surface,
      const RenderDepthStencilSurface* depth_surface);

  // Overridden from Renderer.
  virtual Texture2D::Ref CreatePlatformSpecificTexture2D(
      int width,
      int height,
      Texture::Format format,
      int levels,
      bool enable_render_surfaces);

  // Overridden from Renderer.
  virtual TextureCUBE::Ref CreatePlatformSpecificTextureCUBE(
      int edge_length,
      Texture::Format format,
      int levels,
      bool enable_render_surfaces);
};

}  // namespace o3d

#endif  // O3D_CONVERTER_CROSS_RENDERER_STUB_H_
