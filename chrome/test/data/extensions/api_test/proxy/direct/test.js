// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// proxy api test
// browser_tests.exe --gtest_filter=ExtensionApiTest.ProxyAutoSettings

chrome.test.runTests([
  function setAutoSettings() {
    var config = {
      mode: "direct",
    };
    chrome.experimental.proxy.useCustomProxySettings(config);
    chrome.test.succeed();
  }
]);
