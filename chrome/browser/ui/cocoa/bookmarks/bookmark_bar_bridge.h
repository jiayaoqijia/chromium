// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// C++ bridge class between Chromium and Cocoa to connect the
// Bookmarks (model) with the Bookmark Bar (view).
//
// There is exactly one BookmarkBarBridge per BookmarkBarController /
// BrowserWindowController / Browser.

#ifndef CHROME_BROWSER_UI_COCOA_BOOKMARKS_BOOKMARK_BAR_BRIDGE_H_
#define CHROME_BROWSER_UI_COCOA_BOOKMARKS_BOOKMARK_BAR_BRIDGE_H_
#pragma once

#include "base/basictypes.h"
#include "chrome/browser/bookmarks/bookmark_model_observer.h"

class Browser;
@class BookmarkBarController;

class BookmarkBarBridge : public BookmarkModelObserver {
 public:
  BookmarkBarBridge(BookmarkBarController* controller,
                    BookmarkModel* model);
  virtual ~BookmarkBarBridge();

  // Overridden from BookmarkModelObserver
  virtual void Loaded(BookmarkModel* model);
  virtual void BookmarkModelBeingDeleted(BookmarkModel* model);
  virtual void BookmarkNodeMoved(BookmarkModel* model,
                                 const BookmarkNode* old_parent,
                                 int old_index,
                                 const BookmarkNode* new_parent,
                                 int new_index);
  virtual void BookmarkNodeAdded(BookmarkModel* model,
                                 const BookmarkNode* parent,
                                 int index);
  virtual void BookmarkNodeRemoved(BookmarkModel* model,
                                   const BookmarkNode* parent,
                                   int old_index,
                                   const BookmarkNode* node);
  virtual void BookmarkNodeChanged(BookmarkModel* model,
                                   const BookmarkNode* node);
  virtual void BookmarkNodeFavIconLoaded(BookmarkModel* model,
                                         const BookmarkNode* node);
  virtual void BookmarkNodeChildrenReordered(BookmarkModel* model,
                                             const BookmarkNode* node);

  virtual void BookmarkImportBeginning(BookmarkModel* model);
  virtual void BookmarkImportEnding(BookmarkModel* model);

 private:
  BookmarkBarController* controller_;  // weak; owns me
  BookmarkModel* model_;  // weak; it is owned by a Profile.
  bool batch_mode_;

  DISALLOW_COPY_AND_ASSIGN(BookmarkBarBridge);
};

#endif  // CHROME_BROWSER_UI_COCOA_BOOKMARKS_BOOKMARK_BAR_BRIDGE_H_
