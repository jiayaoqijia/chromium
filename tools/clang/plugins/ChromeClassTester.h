// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_CLANG_PLUGINS_CHROMECLASSTESTER_H_
#define TOOLS_CLANG_PLUGINS_CHROMECLASSTESTER_H_

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/AST.h"
#include "clang/AST/TypeLoc.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"

#include <vector>

// A class on top of ASTConsumer that forwards classes defined in Chromium
// headers to subclasses which implement CheckChromeClass().
class ChromeClassTester : public clang::ASTConsumer {
 public:
  explicit ChromeClassTester(clang::CompilerInstance& instance);
  virtual ~ChromeClassTester();

  // ASTConsumer:
  virtual void HandleTagDeclDefinition(clang::TagDecl* tag);

 protected:
  clang::CompilerInstance& instance() { return instance_; }
  clang::Diagnostic& diagnostic() { return diagnostic_; }

  // Emits a simple warning; this shouldn't be used if you require printf-style
  // printing.
  void emitWarning(clang::SourceLocation loc, const char* error);

 private:
  // Template method which is called with only classes that are defined in
  // chrome header files.
  virtual void CheckChromeClass(const clang::SourceLocation& record_location,
                                clang::CXXRecordDecl* record) = 0;

  // Utility methods used for filtering out non-chrome classes (and ones we
  // delibrately ignore) in HandleTagDeclDefinition().
  bool IsTestCode(clang::Decl* record);
  bool InBannedNamespace(clang::Decl* record);
  std::string GetNamespace(clang::Decl* record);
  std::string GetNamespaceImpl(const clang::DeclContext* context,
                               std::string candidate);
  bool InBannedDirectory(const clang::SourceLocation& loc);
  bool IsIgnoredType(clang::RecordDecl* record);

  clang::CompilerInstance& instance_;
  clang::Diagnostic& diagnostic_;

  // List of banned namespaces.
  std::vector<std::string> banned_namespaces_;

  // List of banned directories.
  std::vector<std::string> banned_directories_;

  // List of types that we don't check.
  std::vector<std::string> ignored_record_names_;
};

#endif  // TOOLS_CLANG_PLUGINS_CHROMECLASSTESTER_H_
