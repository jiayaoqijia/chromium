// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/test/webdriver/session_manager.h"

#include <vector>

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/message_loop_proxy.h"
#include "base/process.h"
#include "base/process_util.h"
#include "base/string_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/test/test_timeouts.h"
#include "base/utf_string_conversions.h"
#include "chrome/app/chrome_command_ids.h"
#include "chrome/common/chrome_constants.h"
#include "chrome/common/chrome_switches.h"
#include "chrome/test/test_launcher_utils.h"
#include "chrome/test/webdriver/utility_functions.h"
#include "third_party/webdriver/atoms.h"

namespace webdriver {

Session::Session(const std::string& id)
    : thread_(id.c_str()),
      id_(id),
      window_num_(0),
      implicit_wait_(0),
      current_frame_xpath_(L"") {
}

bool Session::Init() {
  if (!thread_.Start()) {
    LOG(ERROR) << "Cannot start session thread";
    return false;
  }

  bool success = false;
  RunSessionTask(NewRunnableMethod(
      this,
      &Session::InitOnSessionThread,
      &success));
  return success;
}

void Session::Terminate() {
  RunSessionTask(NewRunnableMethod(
      this,
      &Session::TerminateOnSessionThread));
}

ErrorCode Session::ExecuteScript(const std::wstring& script,
                                 const ListValue* const args,
                                 Value** value) {
  std::string args_as_json;
  base::JSONWriter::Write(static_cast<const Value* const>(args),
                          /*pretty_print=*/false,
                          &args_as_json);

  std::wstring jscript = L"window.domAutomationController.send((function(){" +
      // Every injected script is fed through the executeScript atom. This atom
      // will catch any errors that are thrown and convert them to the
      // appropriate JSON structure.
      build_atom(EXECUTE_SCRIPT, sizeof EXECUTE_SCRIPT) +
      L"var result = executeScript(function(){" + script + L"}," +
      ASCIIToWide(args_as_json) + L");return JSON.stringify(result);})());";

  // Should we also log the script that's being executed? It could be several KB
  // in size and will add lots of noise to the logs.
  VLOG(1) << "Executing script in frame: " << current_frame_xpath_;

  std::wstring result;
  bool success;
  std::string result_utf8;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::ExecuteScript,
      WideToUTF8(current_frame_xpath_),
      WideToUTF8(jscript),
      &result_utf8,
      &success));
  if (!success) {
    *value = Value::CreateStringValue(
        "Unknown internal script execution failure");
    return kUnknownError;
  }
  result = UTF8ToWide(result_utf8);

  VLOG(1) << "...script result: " << result;
  std::string temp = WideToASCII(result);
  scoped_ptr<Value> r(base::JSONReader::ReadAndReturnError(
      temp, true, NULL, NULL));
  if (!r.get()) {
    *value = Value::CreateStringValue(
        "Internal script execution error: failed to parse script result");
    return kUnknownError;
  }

  if (r->GetType() != Value::TYPE_DICTIONARY) {
    std::ostringstream stream;
    stream << "Internal script execution error: script result must be a "
           << print_valuetype(Value::TYPE_DICTIONARY) << ", but was "
           << print_valuetype(r->GetType()) << ": " << result;
    *value = Value::CreateStringValue(stream.str());
    return kUnknownError;
  }

  DictionaryValue* result_dict = static_cast<DictionaryValue*>(r.get());

  Value* tmp;
  if (result_dict->Get("value", &tmp)) {
    // result_dict owns the returned value, so we need to make a copy.
    *value = tmp->DeepCopy();
  } else {
    // "value" was not defined in the returned dictionary, set to null.
    *value = Value::CreateNullValue();
  }

  int status;
  if (!result_dict->GetInteger("status", &status)) {
    NOTREACHED() << "...script did not return a status flag.";
  }
  return static_cast<ErrorCode>(status);
}

bool Session::NavigateToURL(const std::string& url) {
  bool success = false;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::NavigateToURL,
      url,
      &success));
  return success;
}

bool Session::GoForward() {
  bool success = false;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::GoForward,
      &success));
  return success;
}

bool Session::GoBack() {
  bool success = false;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::GoBack,
      &success));
  return success;
}

bool Session::Reload() {
  bool success = false;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::Reload,
      &success));
  return success;
}

bool Session::GetURL(std::string* url) {
  bool success = false;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::GetURL,
      url,
      &success));
  return success;
}

bool Session::GetTabTitle(std::string* tab_title) {
  bool success = false;
  RunSessionTask(NewRunnableMethod(
      automation_.get(),
      &Automation::GetTabTitle,
      tab_title,
      &success));
  return success;
}

void Session::RunSessionTask(Task* task) {
  base::WaitableEvent done_event(false, false);
  thread_.message_loop_proxy()->PostTask(FROM_HERE, NewRunnableMethod(
      this,
      &Session::RunSessionTaskOnSessionThread,
      task,
      &done_event));
  done_event.Wait();
}

void Session::RunSessionTaskOnSessionThread(Task* task,
                                            base::WaitableEvent* done_event) {
  task->Run();
  delete task;
  done_event->Signal();
}

void Session::InitOnSessionThread(bool* success) {
  automation_.reset(new Automation());
  automation_->Init(success);
}

void Session::TerminateOnSessionThread() {
  automation_->Terminate();
  automation_.reset();
}

}  // namespace webdriver
