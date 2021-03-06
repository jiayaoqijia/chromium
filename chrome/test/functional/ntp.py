#!/usr/bin/python
# Copyright (c) 2010 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

import pyauto_functional  # Must be imported before pyauto
import pyauto
import test_utils


class NTPTest(pyauto.PyUITest):
  """Test of the NTP."""

  def Debug(self):
    """Test method for experimentation.

    This method is not run automatically.
    """
    while True:
      raw_input('Interact with the browser and hit <enter> to dump NTP info...')
      print '*' * 20
      import pprint
      pp = pprint.PrettyPrinter(indent=2)
      pp.pprint(self._GetNTPInfo())

  def __init__(self, methodName='runTest'):
    super(NTPTest, self).__init__(methodName)

    # Create some dummy file urls we can use in the tests.
    filenames = ['title1.html', 'title2.html']
    titles = [u'', u'Title Of Awesomeness']
    urls = map(lambda name: self.GetFileURLForDataPath(name), filenames)
    self.PAGES = map(lambda url, title: {'url': url, 'title': title},
                     urls, titles)

  def _NTPContainsThumbnail(self, check_thumbnail):
    """Returns whether the NTP's Most Visited section contains the given
    thumbnail."""
    for thumbnail in self.GetNTPThumbnails():
      if check_thumbnail['url'] == thumbnail['url']:
        return True
    return False

  def testFreshProfile(self):
    """Tests that the NTP with a fresh profile is correct"""
    thumbnails = self.GetNTPThumbnails()
    default_sites = self.GetNTPDefaultSites()
    self.assertEqual(len(default_sites), len(thumbnails))
    for thumbnail, default_site in zip(thumbnails, default_sites):
      self.assertEqual(thumbnail['url'], default_site)
    self.assertEqual(0, len(self.GetNTPRecentlyClosed()))

  def testRemoveDefaultThumbnails(self):
    """Tests that the default thumbnails can be removed"""
    self.RemoveNTPDefaultThumbnails()
    self.assertFalse(self.GetNTPThumbnails())
    self.RestoreAllNTPThumbnails()
    self.assertEqual(len(self.GetNTPDefaultSites()),
                     len(self.GetNTPThumbnails()))
    self.RemoveNTPDefaultThumbnails()
    self.assertFalse(self.GetNTPThumbnails())

  def testOneMostVisitedSite(self):
    """Tests that a site is added to the most visited sites"""
    self.RemoveNTPDefaultThumbnails()
    self.NavigateToURL(self.PAGES[1]['url'])
    thumbnail = self.GetNTPThumbnails()[0]
    self.assertEqual(self.PAGES[1]['url'], thumbnail['url'])
    self.assertEqual(self.PAGES[1]['title'], thumbnail['title'])
    self.assertFalse(thumbnail['is_pinned'])

  def testMoveThumbnailBasic(self):
    """Tests moving a thumbnail to a different index"""
    self.RemoveNTPDefaultThumbnails()
    self.NavigateToURL(self.PAGES[0]['url'])
    self.NavigateToURL(self.PAGES[1]['url'])
    thumbnails = self.GetNTPThumbnails()
    self.MoveNTPThumbnail(thumbnails[0], 1)
    self.assertTrue(self.IsNTPThumbnailPinned(thumbnails[0]))
    self.assertFalse(self.IsNTPThumbnailPinned(thumbnails[1]))
    self.assertEqual(self.PAGES[0]['url'], self.GetNTPThumbnails()[1]['url'])
    self.assertEqual(1, self.GetNTPThumbnailIndex(thumbnails[0]))

  def testPinningThumbnailBasic(self):
    """Tests that we can pin/unpin a thumbnail"""
    self.RemoveNTPDefaultThumbnails()
    self.NavigateToURL(self.PAGES[0]['url'])
    thumbnail1 = self.GetNTPThumbnails()[0]
    self.assertFalse(self.IsNTPThumbnailPinned(thumbnail1))
    self.PinNTPThumbnail(thumbnail1)
    self.assertTrue(self.IsNTPThumbnailPinned(thumbnail1))
    self.UnpinNTPThumbnail(thumbnail1)
    self.assertFalse(self.IsNTPThumbnailPinned(thumbnail1))

  def testRemoveThumbnail(self):
    """Tests removing a thumbnail works"""
    self.RemoveNTPDefaultThumbnails()
    for page in self.PAGES:
      self.AppendTab(pyauto.GURL(page['url']))

    thumbnails = self.GetNTPThumbnails()
    for thumbnail in thumbnails:
      self.assertEquals(thumbnail, self.GetNTPThumbnails()[0])
      self.RemoveNTPThumbnail(thumbnail)
      self.assertFalse(self._NTPContainsThumbnail(thumbnail))
    self.assertFalse(self.GetNTPThumbnails())

  def testIncognitoNotAppearInMostVisited(self):
    """Tests that visiting a page in incognito mode does cause it to appear in
    the Most Visited section"""
    self.RemoveNTPDefaultThumbnails()
    self.RunCommand(pyauto.IDC_NEW_INCOGNITO_WINDOW)
    self.NavigateToURL(self.PAGES[0]['url'], 1, 0)
    self.assertFalse(self.GetNTPThumbnails())

  def testRestoreOncePinnedThumbnail(self):
    """Tests that after restoring a once pinned thumbnail, the thumbnail is
    not pinned"""
    self.RemoveNTPDefaultThumbnails()
    self.NavigateToURL(self.PAGES[0]['url'])
    thumbnail1 = self.GetNTPThumbnails()[0]
    self.PinNTPThumbnail(thumbnail1)
    self.RemoveNTPThumbnail(thumbnail1)
    self.RestoreAllNTPThumbnails()
    self.RemoveNTPDefaultThumbnails()
    self.assertFalse(self.IsNTPThumbnailPinned(thumbnail1))

  def testThumbnailPersistence(self):
    """Tests that thumbnails persist across Chrome restarts"""
    self.RemoveNTPDefaultThumbnails()
    for page in self.PAGES:
      self.AppendTab(pyauto.GURL(page['url']))
    thumbnails = self.GetNTPThumbnails()
    self.MoveNTPThumbnail(thumbnails[0], 1)
    thumbnails = self.GetNTPThumbnails()

    self.RestartBrowser(clear_profile=False)
    self.assertEqual(thumbnails, self.GetNTPThumbnails())

  def testRestoreAllRemovedThumbnails(self):
    """Tests restoring all removed thumbnails"""
    for page in self.PAGES:
      self.AppendTab(pyauto.GURL(page['url']))

    thumbnails = self.GetNTPThumbnails()
    for thumbnail in thumbnails:
      self.RemoveNTPThumbnail(thumbnail)

    self.RestoreAllNTPThumbnails()
    self.assertEquals(thumbnails, self.GetNTPThumbnails())

  def testThumbnailRanking(self):
    """Tests that the thumbnails are ordered according to visit count"""
    self.RemoveNTPDefaultThumbnails()
    for page in self.PAGES:
      self.AppendTab(pyauto.GURL(page['url']))
    thumbnails = self.GetNTPThumbnails()
    self.assertEqual(self.PAGES[0]['url'], self.GetNTPThumbnails()[0]['url'])
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']))
    self.assertEqual(self.PAGES[1]['url'], self.GetNTPThumbnails()[0]['url'])
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']))
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']))
    self.assertEqual(self.PAGES[0]['url'], self.GetNTPThumbnails()[0]['url'])

  def testPinnedThumbnailNeverMoves(self):
    """Tests that once a thumnail is pinned it never moves"""
    self.RemoveNTPDefaultThumbnails()
    for page in self.PAGES:
      self.AppendTab(pyauto.GURL(page['url']))
    self.PinNTPThumbnail(self.GetNTPThumbnails()[0])
    thumbnails = self.GetNTPThumbnails()
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']))
    self.assertEqual(thumbnails, self.GetNTPThumbnails())

  def testThumbnailTitleChangeAfterPageTitleChange(self):
    """Tests that once a page title changes, the thumbnail title changes too"""
    self.RemoveNTPDefaultThumbnails()
    self.NavigateToURL(self.PAGES[0]['url'])
    self.assertEqual(self.PAGES[0]['title'],
                     self.GetNTPThumbnails()[0]['title'])
    self.ExecuteJavascript('window.domAutomationController.send(' +
                           'document.title = "new title")')
    self.assertEqual('new title', self.GetNTPThumbnails()[0]['title'])

  def testCloseOneTab(self):
    """Tests that closing a tab populates the recently closed list"""
    self.RemoveNTPDefaultThumbnails()
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']))
    self.GetBrowserWindow(0).GetTab(1).Close(True)
    self.assertEqual(self.PAGES[1]['url'],
                     self.GetNTPRecentlyClosed()[0]['url'])
    self.assertEqual(self.PAGES[1]['title'],
                     self.GetNTPRecentlyClosed()[0]['title'])

  def testCloseOneWindow(self):
    """Tests that closing a window populates the recently closed list"""
    self.RemoveNTPDefaultThumbnails()
    self.OpenNewBrowserWindow(True)
    self.NavigateToURL(self.PAGES[0]['url'], 1, 0)
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']), 1)
    self.CloseBrowserWindow(1)
    expected = [{ u'type': u'window',
                  u'tabs': [
                  { u'type': u'tab',
                    u'url': self.PAGES[0]['url'],
                    u'direction': u'ltr' },
                  { u'type': u'tab',
                    u'url': self.PAGES[1]['url']}]
                }]
    self.assertEquals(expected, test_utils.StripUnmatchedKeys(
        self.GetNTPRecentlyClosed(), expected))

  def testCloseMultipleTabs(self):
    """Tests closing multiple tabs populates the Recently Closed section in
    order"""
    self.RemoveNTPDefaultThumbnails()
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']))
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']))
    self.GetBrowserWindow(0).GetTab(2).Close(True)
    self.GetBrowserWindow(0).GetTab(1).Close(True)
    expected = [{ u'type': u'tab',
                  u'url': self.PAGES[0]['url']
                },
                { u'type': u'tab',
                  u'url': self.PAGES[1]['url']
                }]
    self.assertEquals(expected, test_utils.StripUnmatchedKeys(
        self.GetNTPRecentlyClosed(), expected))

  def testCloseWindowWithOneTab(self):
    """Tests that closing a window with only one tab only shows up as a tab in
    the Recently Closed section"""
    self.RemoveNTPDefaultThumbnails()
    self.OpenNewBrowserWindow(True)
    self.NavigateToURL(self.PAGES[0]['url'], 1, 0)
    self.CloseBrowserWindow(1)
    expected = [{ u'type': u'tab',
                  u'url': self.PAGES[0]['url']
                }]
    self.assertEquals(expected, test_utils.StripUnmatchedKeys(
        self.GetNTPRecentlyClosed(), expected))

  def testCloseMultipleWindows(self):
    """Tests closing multiple windows populates the Recently Closed list"""
    self.RemoveNTPDefaultThumbnails()
    self.OpenNewBrowserWindow(True)
    self.NavigateToURL(self.PAGES[0]['url'], 1, 0)
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']), 1)
    self.OpenNewBrowserWindow(True)
    self.NavigateToURL(self.PAGES[1]['url'], 2, 0)
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']), 2)
    self.CloseBrowserWindow(2)
    self.CloseBrowserWindow(1)
    expected = [{ u'type': u'window',
                  u'tabs': [
                  { u'type': u'tab',
                    u'url': self.PAGES[0]['url'],
                    u'direction': u'ltr' },
                  { u'type': u'tab',
                    u'url': self.PAGES[1]['url']}]
                },
                { u'type': u'window',
                  u'tabs': [
                  { u'type': u'tab',
                    u'url': self.PAGES[1]['url'],
                    u'direction': u'ltr' },
                  { u'type': u'tab',
                    u'url': self.PAGES[0]['url']}]
                }]
    self.assertEquals(expected, test_utils.StripUnmatchedKeys(
        self.GetNTPRecentlyClosed(), expected))

  def testRecentlyClosedShowsUniqueItems(self):
    """Tests that the Recently Closed section does not show duplicate items"""
    self.RemoveNTPDefaultThumbnails()
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']))
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']))
    self.GetBrowserWindow(0).GetTab(1).Close(True)
    self.GetBrowserWindow(0).GetTab(1).Close(True)
    self.assertEquals(1, len(self.GetNTPRecentlyClosed()))

  def testRecentlyClosedIncognito(self):
    """Tests that we don't record closure of Incognito tabs or windows"""
    #self.RemoveNTPDefaultThumbnails()
    self.RunCommand(pyauto.IDC_NEW_INCOGNITO_WINDOW)
    self.NavigateToURL(self.PAGES[0]['url'], 1, 0)
    self.AppendTab(pyauto.GURL(self.PAGES[0]['url']), 1)
    self.AppendTab(pyauto.GURL(self.PAGES[1]['url']), 1)
    self.GetBrowserWindow(1).GetTab(0).Close(True)
    self.assertFalse(self.GetNTPRecentlyClosed())
    self.CloseBrowserWindow(1)
    self.assertFalse(self.GetNTPRecentlyClosed())


if __name__ == '__main__':
  pyauto_functional.Main()
