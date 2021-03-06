// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "webkit/plugins/ppapi/ppb_video_decoder_impl.h"

#include "base/logging.h"
#include "ppapi/c/dev/pp_video_dev.h"
#include "ppapi/c/dev/ppb_video_decoder_dev.h"
#include "ppapi/c/pp_completion_callback.h"
#include "ppapi/c/pp_errors.h"
#include "webkit/plugins/ppapi/common.h"
#include "webkit/plugins/ppapi/ppapi_plugin_instance.h"
#include "webkit/plugins/ppapi/ppb_file_ref_impl.h"
#include "webkit/plugins/ppapi/resource_tracker.h"

namespace webkit {
namespace ppapi {

namespace {

PP_Bool GetConfig(PP_Instance instance_id,
                  PP_VideoCodecId_Dev codec,
                  PP_VideoConfig_Dev* configs,
                  int32_t config_size,
                  int32_t *num_config) {
  PluginInstance* instance = ResourceTracker::Get()->GetInstance(instance_id);
  *num_config = 0;
  if (!instance)
    return PP_FALSE;

  // Get configs based on codec.

  if (configs) {
    // Fill in the array of configs.
  }

  // Update *num_config.

  return PP_TRUE;
}

PP_Resource Create(PP_Instance instance_id,
                   const PP_VideoDecoderConfig_Dev* decoder_config) {
  PluginInstance* instance = ResourceTracker::Get()->GetInstance(instance_id);
  if (!instance)
    return 0;

  scoped_refptr<PPB_VideoDecoder_Impl> decoder(
      new PPB_VideoDecoder_Impl(instance));

  if (!decoder->Init(*decoder_config))
    return 0;

  return decoder->GetReference();
}

PP_Bool Decode(PP_Resource decoder_id,
               PP_VideoCompressedDataBuffer_Dev* input_buffer) {
  scoped_refptr<PPB_VideoDecoder_Impl> decoder(
      Resource::GetAs<PPB_VideoDecoder_Impl>(decoder_id));
  if (!decoder)
    return PP_FALSE;

  decoder->Decode(*input_buffer);
  return PP_TRUE;
}

int32_t Flush(PP_Resource decoder_id, PP_CompletionCallback callback) {
  scoped_refptr<PPB_VideoDecoder_Impl> decoder(
      Resource::GetAs<PPB_VideoDecoder_Impl>(decoder_id));
  if (!decoder)
    return PP_ERROR_BADRESOURCE;

  return decoder->Flush(callback);
}

PP_Bool ReturnUncompressedDataBuffer(
    PP_Resource decoder_id,
    PP_VideoUncompressedDataBuffer_Dev* buffer) {
  scoped_refptr<PPB_VideoDecoder_Impl> decoder(
      Resource::GetAs<PPB_VideoDecoder_Impl>(decoder_id));
  if (!decoder)
    return PP_FALSE;

  return BoolToPPBool(decoder->ReturnUncompressedDataBuffer(*buffer));
}

const PPB_VideoDecoder_Dev ppb_videodecoder = {
  &GetConfig,
  &Create,
  &Decode,
  &Flush,
  &ReturnUncompressedDataBuffer
};

}  // namespace

PPB_VideoDecoder_Impl::PPB_VideoDecoder_Impl(PluginInstance* instance)
    : Resource(instance) {
}

PPB_VideoDecoder_Impl::~PPB_VideoDecoder_Impl() {
}

// static
const PPB_VideoDecoder_Dev* PPB_VideoDecoder_Impl::GetInterface() {
  return &ppb_videodecoder;
}

PPB_VideoDecoder_Impl* PPB_VideoDecoder_Impl::AsPPB_VideoDecoder_Impl() {
  return this;
}

bool PPB_VideoDecoder_Impl::Init(
    const PP_VideoDecoderConfig_Dev& decoder_config) {
  if (!instance())
    return false;

  platform_video_decoder_.reset(
      instance()->delegate()->CreateVideoDecoder(decoder_config));

  return platform_video_decoder_.get()? true : false;
}

bool PPB_VideoDecoder_Impl::Decode(
    PP_VideoCompressedDataBuffer_Dev& input_buffer) {
  if (!platform_video_decoder_.get())
    return false;

  return platform_video_decoder_->Decode(input_buffer);
}

int32_t PPB_VideoDecoder_Impl::Flush(PP_CompletionCallback& callback) {
  if (!platform_video_decoder_.get())
    return PP_ERROR_FAILED;

  return platform_video_decoder_->Flush(callback);
}

bool PPB_VideoDecoder_Impl::ReturnUncompressedDataBuffer(
    PP_VideoUncompressedDataBuffer_Dev& buffer) {
  if (!platform_video_decoder_.get())
    return false;

  return platform_video_decoder_->ReturnUncompressedDataBuffer(buffer);
}

}  // namespace ppapi
}  // namespace webkit

