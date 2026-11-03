"""Encode string bodies in Cedar syntax, independently of JSON transport."""

from __future__ import annotations


def cedar_string_body(value: str) -> str:
    """Preserve Unicode identity while escaping Cedar delimiters and controls.

    Cedar uses Rust-style escapes, not JSON's four-digit Unicode escapes.
    Do not normalize identities: canonically equivalent strings may name
    different principals. Surrogates are not Unicode scalar values.
    """
    escapes = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    result: list[str] = []
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError("Cedar strings cannot contain Unicode surrogates")
        if character in escapes:
            result.append(escapes[character])
        elif codepoint < 0x20 or codepoint == 0x7F:
            result.append(f"\\u{{{codepoint:x}}}")
        else:
            result.append(character)
    return "".join(result)
