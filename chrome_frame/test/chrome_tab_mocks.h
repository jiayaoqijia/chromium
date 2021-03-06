// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Mock objects for Chrome Frame interfaces.

#ifndef CHROME_FRAME_TEST_CHROME_TAB_MOCKS_H_
#define CHROME_FRAME_TEST_CHROME_TAB_MOCKS_H_

#include "testing/gmock/include/gmock/gmock.h"

// Include without path to make GYP build see it.
#include "chrome_tab.h"  // NOLINT

namespace testing {

class IChromeFramePrivilegedMockImpl : public IChromeFramePrivileged {
 public:
  // Auto-generated by target chrome_frame_privileged_mock
#include "mock_ichromeframeprivileged.gen"  // NOLINT
};

class MockIChromeFramePrivileged
  : public CComObjectRootEx<CComSingleThreadModel>,
    public testing::StrictMock<IChromeFramePrivilegedMockImpl> {
 public:
  DECLARE_NOT_AGGREGATABLE(MockIChromeFramePrivileged)
  BEGIN_COM_MAP(MockIChromeFramePrivileged)
    COM_INTERFACE_ENTRY(IChromeFramePrivileged)
  END_COM_MAP()
  DECLARE_PROTECT_FINAL_CONSTRUCT()

  HRESULT Initialize(MockIChromeFramePrivileged** cfp) {
    *cfp = this;
    return S_OK;
  }
};

}  // namespace testing

#endif  // CHROME_FRAME_TEST_CHROME_TAB_MOCKS_H_
