// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_AUTOFILL_AUTOFILL_IE_TOOLBAR_IMPORT_WIN_H_
#define CHROME_BROWSER_AUTOFILL_AUTOFILL_IE_TOOLBAR_IMPORT_WIN_H_

#include <vector>

// This importer is here and not in chrome/browser/importer/toolbar_importer.cc
// because of the following:
// 1. The data is not saved in profile, but rather in registry, thus it is
//   accessed without going through toolbar front end.
// 2. This applies to IE (thus Windows) toolbar only.
// 3. The functionality relevant only to and completely encapsulated in the
//   autofill.
// 4. This is completely automated as opposed to Importers, which are explicit.
class PersonalDataManager;

bool ImportAutofillDataWin(PersonalDataManager* pdm);

#endif  // CHROME_BROWSER_AUTOFILL_AUTOFILL_IE_TOOLBAR_IMPORT_WIN_H_

