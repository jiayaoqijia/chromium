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


// This file contains implementation for raw-data which may be used
// by the progressive streaming archive system

#include "import/cross/raw_data.h"

#include "base/file_path.h"
#include "base/file_util.h"
#include "core/cross/error.h"
#include "utils/cross/dataurl.h"
#include "utils/cross/file_path_utils.h"

using file_util::OpenFile;
using file_util::CloseFile;
using file_util::GetFileSize;

namespace o3d {

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// RawData class
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

O3D_DEFN_CLASS(RawData, ParamObject);

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
RawData::RawData(ServiceLocator* service_locator,
                 const String &uri,
                 const void *data,
                 size_t length)
    : ParamObject(service_locator), uri_(uri), allow_string_value_(true) {
  // make private copy of data
  data_.reset(new uint8[length]);
  length_ = length;
  memcpy(data_.get(), data, length);
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
RawData::Ref RawData::Create(ServiceLocator* service_locator,
                             const String &uri,
                             const void *data,
                             size_t length) {
  return RawData::Ref(new RawData(service_locator, uri, data, length));
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
RawData::Ref RawData::CreateFromFile(ServiceLocator* service_locator,
                                     const String &uri,
                                     const String& filename) {
  RawData::Ref data(Create(service_locator, uri, NULL, 0));
  if (!data->SetFromFile(filename)) {
    data.Reset();
  }

  return data;
}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
RawData::Ref RawData::CreateFromDataURL(ServiceLocator* service_locator,
                                        const String& data_url) {
  RawData::Ref raw_data(Create(service_locator, "", NULL, 0));
  if (!raw_data->SetFromDataURL(data_url)) {
    raw_data.Reset();
  }

  return raw_data;
}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
RawData::~RawData() {
  Discard();
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool RawData::SetFromFile(const String& filename) {
  // We can't allow general string files to be downloaded from anywhere
  // as that would override the security measures that have been added to
  // XMLHttpRequest over the years. Images and other binary datas are okay.
  // because RawData can only be passed to stuff that understands specific
  // formats.
  allow_string_value_ = false;
  FilePath filepath = UTF8ToFilePath(filename);
  FILE *file = OpenFile(filepath, "rb");
  bool result = false;
  if (!file) {
    DLOG(ERROR) << "file not found \"" << filename << "\"";
  } else {
    // Determine the file's length
    int64 file_size64;
    if (!GetFileSize(filepath, &file_size64)) {
      DLOG(ERROR) << "error getting file size \"" << filename << "\"";
    } else {
      if (file_size64 > 0xffffffffLL) {
        DLOG(ERROR) << "file is too large \"" << filename << "\"";
      } else {
        size_t file_length = static_cast<size_t>(file_size64);

        // Load the file data into memory
        data_.reset(new uint8[file_length]);
        length_ = file_length;
        if (fread(data_.get(), file_length, 1, file) != 1) {
          DLOG(ERROR) << "error reading file \"" << filename << "\"";
        } else {
          result = true;
        }
      }
    }
    CloseFile(file);
  }

  return result;
}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool RawData::SetFromDataURL(const String& data_url) {
  String error_string;
  size_t data_length = 0;
  bool no_errors = dataurl::FromDataURL(data_url,
                                        &data_,
                                        &data_length,
                                        &error_string);
  length_ = data_length;
  if (!no_errors) {
    O3D_ERROR(service_locator()) << error_string;
    return false;
  }
  return true;
}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
const uint8 *RawData::GetData() const {
  // Return data immediately if we have it
  if (data_.get()) {
    return data_.get();
  } else {
    DLOG(ERROR) << "cannot retrieve data object - it has been released";
    return NULL;
  }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

namespace {

// Simple UTF8 validation.
// Params:
//   data: RawData to validate.
//   utf8_length: pointer to size_t to receieve length of UTF8 data.
// Returns:
//   the start of the UTF-8 string or NULL if not valid UTF-8.
const char* GetValidUTF8(const RawData& data, size_t* utf8_length) {
  DCHECK(utf8_length);
  const uint8* s = data.GetDataAs<const uint8>(0);
  if (!s) {
    return NULL;
  }
  size_t length = data.GetLength();

  // Check for BOM and skip it.
  if (length >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF) {
    length -= 3;
    s += 3;
  }

  const uint8* start = s;
  *utf8_length = length;

  while (length) {
    uint8 c = *s++;
    if (c >= 0x80) {
      // It's a multi-byte character
      if (c >= 0xC2 && c <= 0xF4) {
        uint32 codepoint;
        size_t remaining_code_length = 0;
        if ((c & 0xE0) == 0xC0) {
          codepoint = c & 0x1F;
          remaining_code_length = 1;
        } else if ((c & 0xF0) == 0xE0) {
          codepoint = c & 0x0F;
          remaining_code_length = 2;
        } else if ((c & 0xF8) == 0xF0) {
          codepoint = c & 0x07;
          remaining_code_length = 3;
        }
        if (remaining_code_length == 0 || remaining_code_length > length) {
          // Not valid UTF-8
          return NULL;
        }
        length -= remaining_code_length;
        for (size_t cc = 0; cc < remaining_code_length; ++cc) {
          c = *s++;
          if ((c & 0xC0) != 0x80) {
            // Not valid UTF-8
            return NULL;
          }
          codepoint = (codepoint << 6) | (c & 0x3F);
        }
        if (codepoint >= 0xD800 && codepoint < 0xDFFF) {
          // Not valid UTF-8
          return NULL;
        }
      } else {
        // Not valid UTF.
        return NULL;
      }
    } else if (c == 0x00) {
      // It's NULL, not UTF-8
      return NULL;
    }
    --length;
  }
  return reinterpret_cast<const char*>(start);
};

}  // anonymous namespace

String RawData::StringValue() const {
  // NOTE: Originally it was thought to only allow certain extensions.
  // Unfortunately it's not clear what list of extensions are valid. The list of
  // extensions that might be useful to an application is nearly infinite (.txt,
  // .json, .xml, .ini, .csv, .php, .js, .html, .css .xsl, .dae, etc.) So,
  // instead we validate the string is valid UTF-8 AND that there are no NULLs
  // in the string.

  // We can't allow general string files to be downloaded from anywhere
  // as that would override the security measures that have been added to
  // XMLHttpRequest over the years. Images and other binary datas are okay.
  // because RawData can only be passed to stuff that understands specific
  // formats.
  if (!allow_string_value_) {
    O3D_ERROR(service_locator())
        << "You can only get a stringValue from RawDatas inside archives.";
  } else {
    size_t length;
    const char* utf8 = GetValidUTF8(*this, &length);
    if (!utf8) {
      O3D_ERROR(service_locator()) << "RawData is not valid UTF-8 string";
    } else {
      return String (utf8, length);
    }
  }
  return String();
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void RawData::Discard() {
  data_.reset();
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool RawData::IsOffsetLengthValid(size_t offset, size_t length) const {
  if (offset + length < offset) {
    O3D_ERROR(service_locator()) << "overflow";
    return false;
  }
  if (offset + length > length_) {
    O3D_ERROR(service_locator()) << "illegal data offset or size";
    return false;
  }
  return true;
}

}  // namespace o3d
