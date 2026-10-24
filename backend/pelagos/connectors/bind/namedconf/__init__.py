# SPDX-License-Identifier: Apache-2.0
"""Lossless named.conf parser and serializer (section 8).

Contract: serialize(parse(text)) == text for anything named-checkconf accepts;
unknown statements are preserved verbatim; editing keeps surrounding formatting;
`named-checkconf -p` is the oracle in the daemon test tier.
"""

from __future__ import annotations

from pelagos.connectors.bind.namedconf.grammar import context_for, grammar, statement_info, zone_context
from pelagos.connectors.bind.namedconf.lexer import ParseError, Token, tokenize
from pelagos.connectors.bind.namedconf.resolve import (
    MANAGED_FILES,
    MANAGED_HEADER,
    NOTE_PREFIX,
    ConfigFiles,
    build_tree,
    files_tree,
    key_secret,
    load_tree,
    materialize,
    parse,
    resolve_include,
    run_checkconf,
    serialize,
    zone_from_node,
)
from pelagos.connectors.bind.namedconf.tree import (
    ConfigDocument,
    Node,
    canonical,
    compact_text,
    format_statement,
    parse_statements,
    quote,
    unquote,
    word_or_quoted,
)

__all__ = [
    "MANAGED_FILES",
    "MANAGED_HEADER",
    "NOTE_PREFIX",
    "ConfigDocument",
    "ConfigFiles",
    "Node",
    "ParseError",
    "Token",
    "build_tree",
    "canonical",
    "compact_text",
    "context_for",
    "files_tree",
    "format_statement",
    "grammar",
    "key_secret",
    "load_tree",
    "materialize",
    "parse",
    "parse_statements",
    "quote",
    "resolve_include",
    "run_checkconf",
    "serialize",
    "statement_info",
    "tokenize",
    "unquote",
    "word_or_quoted",
    "zone_context",
    "zone_from_node",
]
