// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_GEOLOCATION_GATEWAY_DATA_PROVIDER_WIN_H_
#define CHROME_BROWSER_GEOLOCATION_GATEWAY_DATA_PROVIDER_WIN_H_
#pragma once

#include "chrome/browser/geolocation/gateway_data_provider_common.h"

class WinGatewayDataProvider : public GatewayDataProviderCommon {
 public:
  WinGatewayDataProvider();

 private:
  virtual ~WinGatewayDataProvider();

  // GatewayDataProviderCommon
  virtual GatewayApiInterface* NewGatewayApi();

  DISALLOW_COPY_AND_ASSIGN(WinGatewayDataProvider);
};

#endif //CHROME_BROWSER_GEOLOCATION_GATEWAY_DATA_PROVIDER_WIN_H_
