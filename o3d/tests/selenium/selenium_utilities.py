#!/usr/bin/python2.4
# Copyright 2009, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""Utility scripts for selenium.

A collection of utility scripts for selenium test cases to use.
"""


import os
import re
import time
import unittest
import base64
import gflags
import selenium_constants


FLAGS = gflags.FLAGS
SUFFIXES = ["small", "medium", "large"]


def IsValidTestType(test_type):
  """Returns True if test_type is a "small", "medium" or "large"."""
  return test_type.lower() in SUFFIXES


def IsValidSuffix(name):
  """Returns True if name ends in a valid test type."""
  name = name.lower()
  for suffix in SUFFIXES:
    if name.endswith(suffix):
      return True
  return False

def ScreenshotNameFromTestName(name):
  name = StripTestTypeSuffix(name)

  if name.startswith("Test"):
    # Make sure these are in order.
    prefixes = ["TestStress", "TestSample", "Test"]
    for prefix in prefixes:
      if name.startswith(prefix):
        name = name[len(prefix):]
        break

    # Lowercase the name only for custom test methods.
    name = name.lower()
  
  name = name.replace("_", "-")
  name = name.replace("/", "_")

  return name 


def StripTestTypeSuffix(name):
  """Removes the suffix from name if it is a valid test type."""
  name_lower = name.lower()
  for suffix in SUFFIXES:
    if name_lower.endswith(suffix):
      return name[:-len(suffix)]
  return name


def GetArgument(string):
  """Returns the value inside the first set of parentheses in a string.

  Args:
    string: String in the format "identifier(args)"

  Returns:
    args from string passed in. None if there were no parentheses.
  """
  match = re.match("\w+\(([^)]+)\)", string)
  if match:
    return match.group(1)
  return None


def TakeScreenShot(session, browser, client, filename):
  """Takes a screenshot of the o3d display buffer.

  This function is the preferred way to capture an image of the plugin.

  Uses gflags:
  If gflags.FLAGS.screenshots is False then screen shots will not be taken.
  gflags.FLAGS.screenshotsdir must be set to the path to save screenshots in.

  Args:
    session: Selenium session.
    browser: Name of the browser running the test.
    client: String that in javascript will return the o3d client.
    filename: Name of screenshot.
  Returns:
    success: True on success, False on failure.
  """
  # If screenshots enabled
  if gflags.FLAGS.screenshots:
    full_path = os.path.join(os.getcwd(),
                             FLAGS.screenshotsdir,
                             filename)
    return TakeScreenShotAtPath(session,
                                browser,
                                client,
                                full_path)
  else:
    # Screenshots not enabled, return true (success).
    return True


def TakeScreenShotAtPath(session,
                         browser,
                         client,
                         filename):
  """Takes a screenshot of the o3d display buffer.

  This should be used by tests that need to specify exactly where to save the
  image or don't want to use gflags.

  Args:
    session: Selenium session.
    browser: Name of the browser running the test.
    client: String that in javascript will return the o3d client.
    filename: Full path to screenshot to be saved.

  Returns:
    success: True on success, False on failure.
  """
  session.window_focus()

  # Resize window, and client area if needed.
  session.run_script(
      "(function() {\n"
      "  var needResize = false;\n"
      "  var divs = window.document.getElementsByTagName('div');\n"
      "  for (var ii = 0; ii < divs.length; ++ii) {\n"
      "    var div = divs[ii];\n"
      "    if (div.id && div.id == 'o3d') {\n"
      "      var widthSpec = div.style.width;\n"
      "      if (widthSpec.indexOf('%') >= 0) {\n"
      "        div.style.width = '800px';\n"
      "        div.style.height = '600px';\n"
      "        needResize = true;\n"
      "        break;\n"
      "      }\n"
      "    }\n"
      "  }\n"
      "  window.o3d_seleniumNeedResize = needResize;\n"
      "} ());\n")

  need_client_resize = (
      session.get_eval("window.o3d_seleniumNeedResize") == "true")
  if need_client_resize:
    session.wait_for_condition(
        "window.%s.width == 800 && window.%s.height == 600" % (client, client),
        20000)
  else:
    session.run_script("window.resizeTo(%d, %d)" %
                       (selenium_constants.RESIZE_WIDTH,
                        selenium_constants.RESIZE_HEIGHT))

  # Execute screenshot capture code

  # Replace all backslashes with forward slashes so it is parsed correctly
  # by Javascript
  full_path = filename.replace("\\", "/")

  # Attempt to take a screenshot of the display buffer
  eval_string = ("%s.toDataURL()" % client)


  # Set Post render call back to take screenshot
  script = ["window.g_selenium_post_render = false;",
            "window.g_selenium_save_screen_result = false;",
            "var frameCount = 0;",
            "%s.setPostRenderCallback(function() {" % client,
            "  ++frameCount;",
            "  if (frameCount >= 3) {",
            "    %s.clearPostRenderCallback();" % client,
            "    window.g_selenium_save_screen_result = %s;" % eval_string,
            "    window.g_selenium_post_render = true;",
            "  } else {",
            "    %s.render()" % client,
            "  }",
            "})",
            "%s.render()" % client]
  session.run_script("\n".join(script))
  # Wait for screenshot to be taken.
  session.wait_for_condition("window.g_selenium_post_render", 20000)

  # Get result
  data_url = session.get_eval("window.g_selenium_save_screen_result")
  expected_header = "data:image/png;base64,"
  if data_url.startswith(expected_header):
    png = base64.b64decode(data_url[len(expected_header):])
    file = open(full_path + ".png", 'wb')
    file.write(png)
    file.close()
    return True

  return False


class SeleniumTestCase(unittest.TestCase):
  """Wrapper for TestCase for selenium."""

  def __init__(self, name, browser, path_to_html, test_type=None,
              sample_path=None, options=None):
    """Constructor for SampleTests.

    Args:
      name: Name of unit test.
      session: Selenium session.
      browser: Name of browser.
      path_to_html: path to html from server root
      test_type: Type of test ("small", "medium", "large")
      sample_path: Path to test.
      load_timeout: Time to wait for page to load (ms).
      run_timeout: Time to wait for test to run.
      options: list of option strings.
    """

    unittest.TestCase.__init__(self, name)
    self.name = name
    self.session = None
    self.browser = browser
    self.test_type = test_type
    self.sample_path = sample_path
    self.path_to_html = path_to_html
    self.screenshots = []
    self.load_timeout = 10000
    self.run_timeout = None
    self.client = "g_client"
    # parse options
    for option in options:
      if option.startswith("screenshots"):
        for i in range(int(GetArgument(option))):
          self.screenshots.append("27.5")
      elif option.startswith("screenshot"):
        clock = GetArgument(option)
        if clock is None:
          clock = "27.5"
        self.screenshots.append(clock)
      elif option.startswith("timeout"):
        self.load_timeout = int(GetArgument(option))
      elif option.startswith("client"):
        self.client = GetArgument(option)
      elif option.startswith("run_time"):
        self.run_timeout = int(GetArgument(option))
    
    if self.run_timeout is None:
      # Estimate how long this test needs to run.    
      time_per_screenshot = 10000
      if browser == "*iexplore":
        time_per_screenshot = 60000
      self.run_timeout = 25000 + len(self.screenshots) * time_per_screenshot

  def SetSession(self, session):
    self.session = session

  def GetTestTimeout(self):
    return self.load_timeout + self.run_timeout

  def GetURL(self, url):
    """Gets a URL for the test."""
    return self.session.browserURL + self.path_to_html + url

  def shortDescription(self):
    """override unittest.TestCase shortDescription for our own descriptions."""
    if self.sample_path:
      return "Testing: " + self.sample_path + ".html"
    else:
      return unittest.TestCase.shortDescription(self)

  def RunGenericTest(self, base_path, ready_condition, assertion):
    """Runs a generic test.

    Args:
      base_path: path for sample.
      ready_condition: condition to check in javascript to know sample is ready.
      assertion: javascript to check equals "true"

    Assumes self.sample_path is a path to the html page to load and that
    samples.options is an array of option strings.

    If the sample is animated, it is expected to have a global variable
    called g_timeMult that can be set to 0 to stop the animation.  All of its
    animation must be based on a global variable called g_clock, such that
    setting g_clock to the same value will always produce the same image.

    Finally, each sample is expected to have a global variable called
    g_client which is the o3d client object for that sample.  This is
    used to take a screenshot.
    """
    self.assertTrue(not self.load_timeout is None)
    self.assertTrue(not self.client is None)
    self.assertTrue(self.test_type in ["small", "medium", "large"])

    url = self.GetURL(base_path + self.sample_path + ".html")

    # load the sample.
    self.session.open(url)

    # wait for it to initialize.
    self.session.wait_for_condition(ready_condition, self.load_timeout)

    self.session.run_script(
        "if (window.o3d_prepForSelenium) { window.o3d_prepForSelenium(); }")

    if assertion:
      self.assertEqual("true", self.session.get_eval(assertion))

    # take a screenshot.
    screenshot_id = 1
    for clock in self.screenshots:
      # if they are animated we need to stop the animation and set the clock
      # to some time so we get a known state.
      self.session.run_script("g_timeMult = 0")
      self.session.run_script("g_clock = " + clock)

      # take a screenshot.
      screenshot = self.sample_path.replace("_", "-").replace("/", "_")
      screenshot += str(screenshot_id)
      self.assertTrue(TakeScreenShot(self.session, self.browser,
                                     self.client, screenshot))
      screenshot_id += 1
