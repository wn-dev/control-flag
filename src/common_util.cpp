// Copyright (c) 2021 Niranjan Hasabnis and Justin Gottschlich
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <fstream>
#include <iostream>
#include <sstream>

#include "parser.h"
#include "common_util.h"

template <Language L>
ManagedTSTree GetTSTree(const std::string& source_code,
                        bool report_parse_errors) {
  // Make parser thread-local so that we do not need to delete and recreate it
  // for every file to be parsed.
  thread_local ParserBase<L> parser_base;
  TSParser* parser = parser_base.GetTSParser();

  TSTree *tree = ts_parser_parse_string(parser, nullptr,
                                        source_code.c_str(),
                                        source_code.length());
  parser_base.ResetTSParser();
  if (report_parse_errors && tree == NULL) {
    throw cf_parse_error(source_code);
  } else if (tree == NULL) {
    throw cf_unexpected_situation("Parse error");
  }

  // We do not check if there is a parse error at file-level, all that we need
  // to check is that conditional statements do not have parse error.
  auto root_node = ts_tree_root_node(tree);

  if (report_parse_errors &&
      (ts_node_is_null(root_node) || ts_node_has_error(root_node))) {
    throw cf_parse_error(source_code);
  }

  return ManagedTSTree(tree);
}

template <Language L>
ManagedTSTree GetTSTree(const std::string& source_file,
                        std::string& file_contents) {
  std::ifstream ifs(source_file.c_str());
  if (!ifs.is_open()) {
    throw cf_file_access_exception("Could not open " + source_file);
  }

  std::stringstream buffer;
  buffer << ifs.rdbuf();
  file_contents = buffer.str();

  // We do not report parse errors at file-level. In our case, source code file
  // may contain parse errors. What we look for is control structures do not
  // have parse errors.
  static bool kReportParseError = false;
  return GetTSTree<L>(file_contents, kReportParseError);
}

// For C language, we are looking for control structures such as if statements.
template <>
void CollectCodeBlocksOfInterest<LANGUAGE_C>(const TSNode& node,
    code_blocks_t& code_blocks) {
  if (ts_node_is_null(node)) { return; }

  uint32_t count = ts_node_child_count(node);
  for (uint32_t i = 0; i < count; i++) {
    auto child = ts_node_child(node, i);
    if (ts_node_is_null(child)) continue;
    if (IsIfStatement<LANGUAGE_C>(child)) {
      auto if_condition = GetIfConditionNode<LANGUAGE_C>(child);
      if (!ts_node_has_error(if_condition)) {
        code_blocks.push_back(if_condition);
      }
    }
    CollectCodeBlocksOfInterest<LANGUAGE_C>(child, code_blocks);
  }
}

// For Verilog language, we are looking for always blocks.
template <>
void CollectCodeBlocksOfInterest<LANGUAGE_VERILOG>(const TSNode& node,
    code_blocks_t& code_blocks) {
  if (ts_node_is_null(node)) { return; }

  uint32_t count = ts_node_child_count(node);
  for (uint32_t i = 0; i < count; i++) {
    auto child = ts_node_child(node, i);
    if (ts_node_is_null(child)) continue;
    if (IsAlwaysBlock(child)) {
      code_blocks.push_back(child);
    }
    CollectCodeBlocksOfInterest<LANGUAGE_VERILOG>(child, code_blocks);
  }
}

template <Language L>
void CollectCodeBlocksOfInterest(const ManagedTSTree& tree,
    code_blocks_t& code_blocks) {
  auto root_node = ts_tree_root_node(tree.get());
  CollectCodeBlocksOfInterest<L>(root_node, code_blocks);
}

template
ManagedTSTree GetTSTree<LANGUAGE_C>(const std::string&, bool);
template
ManagedTSTree GetTSTree<LANGUAGE_VERILOG>(const std::string&, bool);
template
ManagedTSTree GetTSTree<LANGUAGE_C>(const std::string&, std::string&);
template
ManagedTSTree GetTSTree<LANGUAGE_VERILOG>(const std::string&, std::string&);
template
void CollectCodeBlocksOfInterest<LANGUAGE_C>(const ManagedTSTree&,
                                             code_blocks_t&);
template
void CollectCodeBlocksOfInterest<LANGUAGE_VERILOG>(const ManagedTSTree &,
                                                   code_blocks_t&);

#ifdef _WIN32

#define ERR(szz, czz) if (opterr) { \
        fprintf(stderr, "%s%s%c\n", argv[0], szz, czz); \
    }

int opterr = 1;
int optind = 1;
int optopt;
char* optarg;

int
getopt(int argc, char* const* argv, const char* opts) {
    static int sp = 1;
    int c;
    const char* cp;

    if (sp == 1) {
        if (optind >= argc ||
            argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return (EOF);
        } else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return (EOF);
        }
    }
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(opts, c)) == NULL) {
        ERR(": illegal option -- ", c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return ('?');
    }
    if (*++cp == ':') {
        if (argv[optind][sp + 1] != '\0') {
            optarg = &argv[optind++][sp + 1];
        } else if (++optind >= argc) {
            ERR(": option requires an argument -- ", c);
            sp = 1;
            return ('?');
        } else {
            optarg = argv[optind++];
        }
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return (c);
}
#endif
