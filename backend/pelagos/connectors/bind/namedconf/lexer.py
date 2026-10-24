# SPDX-License-Identifier: Apache-2.0
"""Lossless tokenizer for named.conf: every byte of the input lands in exactly one token."""

from __future__ import annotations

from dataclasses import dataclass

WHITESPACE = " \t\r\n\f\v"
SPECIALS = "{};"


class ParseError(ValueError):
    def __init__(self, message: str, line: int, path: str | None = None) -> None:
        where = f"{path}:{line}" if path else f"line {line}"
        super().__init__(f"{where}: {message}")
        self.line = line
        self.path = path


@dataclass(slots=True)
class Token:
    kind: str  # "space" | "comment" | "word" | "string" | "lbrace" | "rbrace" | "semi"
    text: str
    line: int


def _comment_starts(text: str, i: int) -> bool:
    return text.startswith("//", i) or text.startswith("/*", i)


def tokenize(text: str, path: str | None = None) -> list[Token]:
    """Comments (`//`, `#`, `/* */`), quoted strings, braces, semicolons and bare words; whitespace kept."""
    tokens: list[Token] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c in WHITESPACE:
            j = i + 1
            while j < n and text[j] in WHITESPACE:
                j += 1
            tokens.append(Token("space", text[i:j], line))
            line += text.count("\n", i, j)
            i = j
        elif c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            tokens.append(Token("comment", text[i:j], line))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ParseError("unterminated block comment", line, path)
            j += 2
            tokens.append(Token("comment", text[i:j], line))
            line += text.count("\n", i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                # A backslash escapes the next character, so an escaped quote does not end the string.
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ParseError("unterminated quoted string", line, path)
            tokens.append(Token("string", text[i : j + 1], line))
            line += text.count("\n", i, j)
            i = j + 1
        elif c == "{":
            tokens.append(Token("lbrace", c, line))
            i += 1
        elif c == "}":
            tokens.append(Token("rbrace", c, line))
            i += 1
        elif c == ";":
            tokens.append(Token("semi", c, line))
            i += 1
        else:
            j = i + 1
            while j < n and text[j] not in WHITESPACE and text[j] not in SPECIALS and text[j] != '"':
                if _comment_starts(text, j):
                    break
                j += 1
            tokens.append(Token("word", text[i:j], line))
            i = j
    return tokens
