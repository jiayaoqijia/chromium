// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/service/service_process_prefs.h"

#include "base/values.h"

ServiceProcessPrefs::ServiceProcessPrefs(
    const FilePath& pref_filename,
    base::MessageLoopProxy* file_message_loop_proxy)
    : prefs_(new JsonPrefStore(pref_filename, file_message_loop_proxy)) {
}

void ServiceProcessPrefs::ReadPrefs() {
  prefs_->ReadPrefs();
}

void ServiceProcessPrefs::WritePrefs() {
  prefs_->WritePrefs();
}

void ServiceProcessPrefs::GetString(const std::string& key,
                                    std::string* result) {
  Value* value;
  if (prefs_->GetValue(key, &value) == PersistentPrefStore::READ_OK)
    value->GetAsString(result);
}

void ServiceProcessPrefs::SetString(const std::string& key,
                                    const std::string& value) {
  prefs_->SetValue(key, Value::CreateStringValue(value));
}

void ServiceProcessPrefs::GetBoolean(const std::string& key, bool* result) {
  Value* value;
  if (prefs_->GetValue(key, &value) == PersistentPrefStore::READ_OK)
    value->GetAsBoolean(result);
}

void ServiceProcessPrefs::SetBoolean(const std::string& key, bool value) {
  prefs_->SetValue(key, Value::CreateBooleanValue(value));
}

void ServiceProcessPrefs::GetDictionary(const std::string& key,
                                        DictionaryValue** result) {
  Value* value;
  if (prefs_->GetValue(key, &value) != PersistentPrefStore::READ_OK ||
      !value->IsType(Value::TYPE_DICTIONARY)) {
    return;
  }

  *result = static_cast<DictionaryValue*>(value);
}
