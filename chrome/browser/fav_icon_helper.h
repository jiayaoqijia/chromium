// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_FAV_ICON_HELPER_H__
#define CHROME_BROWSER_FAV_ICON_HELPER_H__
#pragma once

#include <map>

#include "base/basictypes.h"
#include "base/callback.h"
#include "base/ref_counted.h"
#include "chrome/browser/cancelable_request.h"
#include "chrome/browser/favicon_service.h"
#include "chrome/browser/tab_contents/tab_contents_observer.h"
#include "chrome/common/ref_counted_util.h"
#include "googleurl/src/gurl.h"

class NavigationEntry;
class Profile;
class RefCountedMemory;
class SkBitmap;
class TabContents;

// FavIconHelper is used to fetch the favicon for TabContents.
//
// FetchFavIcon requests the favicon from the favicon service which in turn
// requests the favicon from the history database. At this point
// we only know the URL of the page, and not necessarily the url of the
// favicon. To ensure we handle reloading stale favicons as well as
// reloading a favicon on page reload we always request the favicon from
// history regardless of whether the NavigationEntry has a favicon.
//
// After the navigation two types of events are delivered (which is
// first depends upon who is faster): notification from the history
// db on our request for the favicon (OnFavIconDataForInitialURL),
// or a message from the renderer giving us the URL of the favicon for
// the page (SetFavIconURL).
// . If the history db has a valid up to date favicon for the page, we update
//   the NavigationEntry and use the favicon.
// . When we receive the favicon url if it matches that of the NavigationEntry
//   and the NavigationEntry's favicon is set, we do nothing (everything is
//   ok).
// . On the other hand if the database does not know the favicon for url, or
//   the favicon is out date, or the URL from the renderer does not match that
//   NavigationEntry we proceed to DownloadFavIconOrAskHistory. Before we
//   invoke DownloadFavIconOrAskHistory we wait until we've received both
//   the favicon url and the callback from history. We wait to ensure we
//   truly know both the favicon url and the state of the database.
//
// DownloadFavIconOrAskHistory does the following:
// . If we have a valid favicon, but it is expired we ask the renderer to
//   download the favicon.
// . Otherwise we ask the history database to update the mapping from
//   page url to favicon url and call us back with the favicon. Remember, it is
//   possible for the db to already have the favicon, just not the mapping
//   between page to favicon url. The callback for this is OnFavIconData.
//
// OnFavIconData either updates the favicon of the NavigationEntry (if the
// db knew about the favicon), or requests the renderer to download the
// favicon.
//
// When the renderer downloads the favicon SetFavIconImageData is invoked,
// at which point we update the favicon of the NavigationEntry and notify
// the database to save the favicon.

class FavIconHelper : public TabContentsObserver {
 public:
  explicit FavIconHelper(TabContents* tab_contents);
  virtual ~FavIconHelper();

  // Initiates loading the favicon for the specified url.
  void FetchFavIcon(const GURL& url);

  // Initiates loading an image from given |image_url|. Returns a download id
  // for caller to track the request. When download completes, |callback| is
  // called with the three params: the download_id, a boolean flag to indicate
  // whether the download succeeds and a SkBitmap as the downloaded image.
  // Note that |image_size| is a hint for images with multiple sizes. The
  // downloaded image is not resized to the given image_size. If 0 is passed,
  // the first frame of the image is returned.
  typedef Callback3<int, bool, const SkBitmap&>::Type ImageDownloadCallback;
  int DownloadImage(const GURL& image_url, int image_size,
                    ImageDownloadCallback* callback);

 private:
  struct DownloadRequest {
    DownloadRequest() {}
    DownloadRequest(const GURL& url,
                    const GURL& image_url,
                    ImageDownloadCallback* callback)
        : url(url),
          image_url(image_url),
          callback(callback) { }

    GURL url;
    GURL image_url;
    ImageDownloadCallback* callback;
  };

  // TabContentsObserver implementation.
  virtual bool OnMessageReceived(const IPC::Message& message);

  void OnDidDownloadFavIcon(int id,
                            const GURL& image_url,
                            bool errored,
                            const SkBitmap& image);
  void OnUpdateFavIconURL(int32 page_id, const GURL& icon_url);

  // Return the NavigationEntry for the active entry, or NULL if the active
  // entries URL does not match that of the URL last passed to FetchFavIcon.
  NavigationEntry* GetEntry();

  Profile* profile();

  FaviconService* GetFaviconService();

  // See description above class for details.
  void OnFavIconDataForInitialURL(FaviconService::Handle handle,
                                  bool know_favicon,
                                  scoped_refptr<RefCountedMemory> data,
                                  bool expired,
                                  GURL icon_url);

  // If the favicon has expired, asks the renderer to download the favicon.
  // Otherwise asks history to update the mapping between page url and icon
  // url with a callback to OnFavIconData when done.
  void DownloadFavIconOrAskHistory(NavigationEntry* entry);

  // See description above class for details.
  void OnFavIconData(FaviconService::Handle handle,
                     bool know_favicon,
                     scoped_refptr<RefCountedMemory> data,
                     bool expired,
                     GURL icon_url);

  // Schedules a download for the specified entry. This adds the request to
  // download_requests_.
  int ScheduleDownload(const GURL& url, const GURL& image_url, int image_size,
                       ImageDownloadCallback* callback);

  // Sets the image data for the favicon. This is invoked asynchronously after
  // we request the TabContents to download the favicon.
  void SetFavIcon(const GURL& url, const GURL& icon_url, const SkBitmap& image);

  // Converts the image data to an SkBitmap and sets it on the NavigationEntry.
  // If the TabContents has a delegate, it is notified of the new favicon
  // (INVALIDATE_FAVICON).
  void UpdateFavIcon(NavigationEntry* entry,
                     scoped_refptr<RefCountedMemory> data);
  void UpdateFavIcon(NavigationEntry* entry, const SkBitmap& image);

  // Scales the image such that either the width and/or height is 16 pixels
  // wide. Does nothing if the image is empty.
  SkBitmap ConvertToFavIconSize(const SkBitmap& image);

  // Returns true if the favicon should be saved.
  bool ShouldSaveFavicon(const GURL& url);

  // Hosting TabContents. We callback into this when done.
  TabContents* tab_contents_;

  // Used for history requests.
  CancelableRequestConsumer cancelable_consumer_;

  // URL of the page we're requesting the favicon for.
  GURL url_;

  // Whether we got the url for the page back from the renderer.
  // See "Favicon Details" in tab_contents.cc for more details.
  bool got_fav_icon_url_;

  // Whether we got the initial response for the favicon back from the renderer.
  // See "Favicon Details" in tab_contents.cc for more details.
  bool got_fav_icon_from_history_;

  // Whether the favicon is out of date. If true, it means history knows about
  // the favicon, but we need to download the favicon because the icon has
  // expired.
  // See "Favicon Details" in tab_contents.cc for more details.
  bool fav_icon_expired_;

  // Requests to the renderer to download favicons.
  typedef std::map<int, DownloadRequest> DownloadRequests;
  DownloadRequests download_requests_;

  DISALLOW_COPY_AND_ASSIGN(FavIconHelper);
};

#endif  // CHROME_BROWSER_FAV_ICON_HELPER_H__
