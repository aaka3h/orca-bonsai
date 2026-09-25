"""Convert terminal output to inert, readable plain text without executing it."""
from __future__ import annotations


def sanitize_terminal_text(text: str) -> str:
    """Strip ANSI/C1 controls while retaining Unicode and diagnostic text.

    Carriage-return redraws become newlines instead of overwriting previous output.
    OSC hyperlinks retain their visible labels, while titles/clipboard payloads and
    other terminal string commands are removed. Cursor movement is not emulated.
    """
    if not isinstance(text, str):
        raise TypeError("terminal text must be a string")
    out = []
    index, size = 0, len(text)
    while index < size:
        character = text[index]
        code = ord(character)
        if character == "\r":
            out.append("\n")
            index += 2 if index + 1 < size and text[index + 1] == "\n" else 1
            continue
        if character == "\x85":
            out.append("\n")
            index += 1
            continue
        if character == "\x1b" or character in {"\x90", "\x98", "\x9b", "\x9d", "\x9e", "\x9f"}:
            if character == "\x1b":
                if index + 1 >= size:
                    break
                introducer = text[index + 1]
                position = index + 2
            else:
                introducer = {"\x90": "P", "\x98": "X", "\x9b": "[", "\x9d": "]", "\x9e": "^", "\x9f": "_"}[character]
                position = index + 1
            if introducer == "[":
                # CSI parameters/intermediates end at one ASCII final byte.
                while position < size and 0x20 <= ord(text[position]) <= 0x3f:
                    position += 1
                if position < size and 0x40 <= ord(text[position]) <= 0x7e:
                    position += 1
                index = position
                continue
            if introducer in {"]", "P", "X", "^", "_"}:
                # OSC ends at BEL or ST; DCS/SOS/PM/APC use ST. An unterminated
                # terminal command's payload remains hidden rather than displayed.
                while position < size:
                    if text[position] == "\x9c" or (introducer == "]" and text[position] == "\x07"):
                        position += 1
                        break
                    if text[position] == "\x1b" and position + 1 < size and text[position + 1] == "\\":
                        position += 2
                        break
                    position += 1
                index = position
                continue
            if character == "\x1b":
                # Other standard escape sequences: ESC, optional intermediate
                # bytes, final byte. Preserve non-ASCII text after a stray ESC.
                position = index + 1
                while position < size and 0x20 <= ord(text[position]) <= 0x2f:
                    position += 1
                if position < size and 0x30 <= ord(text[position]) <= 0x7e:
                    position += 1
                index = max(index + 1, position)
                continue
        if character in {"\n", "\t"} or (code >= 0x20 and not 0x7f <= code <= 0x9f):
            out.append(character)
        index += 1
    return "".join(out)


# Deliberately anchored recognizers: mentioning an error in ordinary prose does
# not itself make a command unsuccessful.
import re

_HTML_DOCUMENT = re.compile(r"<(?:!doctype\s+html|html|head|body|main|title|pre|code|div|p|article)(?:\s|>)", re.I)
_REASON = (r"(?:permission denied|operation not permitted|(?:device or resource|resource|device) busy|"
           r"(?:operation|function|protocol|address family) not supported|unsupported (?:operation|option|argument)|"
           r"invalid (?:option|argument|command|parameter)|(?:unrecognized|unknown|illegal) (?:option|argument)|"
           r"no such (?:file|device)|network is down|command not found)")
_PROGRAM = r"(?:/[\w.+~@%/-]+|[A-Za-z0-9_.+-]{1,64})"
_CLI_DIAGNOSTIC = re.compile(
    r"^\s*(?:"
    r"\|[ _|+-]*[\w.-]+:\s*ERROR:\s+\S|"
    r"NSE:\s*(?:failed|error)\b|"
    r"curl:\s*\([1-9]\d*\)\s+\S|"
    r"(?:nmap|dig|host|nslookup|whois|openssl|wget|sudo|timeout):\s+"
    r"[^\n]*(?:\berror\b|\bfailed\b|\bcannot\b|\bcould not\b|\bnot found\b|\bpermission denied\b|\bno such file\b)|"
    r"(?:(?:/[^:\s]+/)?(?:ba|z|da|k)?sh):\s+[^\n]*"
    r"(?:\bcommand not found\b|\bpermission denied\b|\bsyntax error\b|\bno such file or directory\b)|"
    r"command failed:\s*" + _REASON + r"\b|"
    r"(?:ioctl\([^()\n]{1,100}\)|(?:read|write|open|bind|connect|socket|setsockopt|getsockopt)(?:\([^()\n]{0,100}\))?)\s+failed:\s*" + _REASON + r"\b|"
    r"(?:" + _PROGRAM + r":\s*)?(?:error|fatal):\s*" + _REASON + r"\b|"
    + _PROGRAM + r":\s*(?:(?:'[^'\n]{1,180}'|\"[^\"\n]{1,180}\"|[~./][^:\n]{1,180}):\s*)?" + _REASON + r"\b|"
    r"Notice:\s+You specified [^\n]{1,180}\. Did you mean [^\n]{1,180} instead\?"
    r")", re.I,
)
_QUOTED_INTRO = re.compile(
    r"^\s*(?:(?:#{1,6}\s+)?(?:example(?:s)?|sample|quoted|expected)(?:\s+(?:output|error|diagnostic|message|text|code))*\s*:|"
    r"(?:the\s+)?(?:documentation|manual|reference|readme)[^\n]{0,100}\b(?:says|shows|includes|example)[^\n]{0,80}:)\s*$", re.I,
)


def extract_cli_errors(text: str) -> list[str]:
    """Return at most 16 distinct, sanitized CLI diagnostic lines (512 chars).

    HTML documents, Markdown examples/fences/quotes and indented code are excluded.
    This is stateless: callers splitting a stream must preserve line and document
    context; a fragment alone cannot reveal an earlier quote or fence opener.
    """
    cleaned = sanitize_terminal_text(text)
    if _HTML_DOCUMENT.search(cleaned):
        return []
    errors, seen = [], set()
    fence = None
    quoted_example = False
    for line in cleaned.splitlines():
        stripped = line.strip()
        marker = re.match(r"^(`{3,}|~{3,})", stripped)
        if marker:
            current = marker.group(1)
            if fence is None:
                fence = current
            elif current[0] == fence[0] and len(current) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        if not stripped:
            quoted_example = False
            continue
        if _QUOTED_INTRO.match(line):
            quoted_example = True
            continue
        if quoted_example or line.startswith(("    ", "\t")) or stripped.startswith((">", "'", '"', "`")):
            continue
        if _CLI_DIAGNOSTIC.search(line):
            diagnostic = " ".join(stripped.split())[:512]
            if diagnostic not in seen:
                seen.add(diagnostic)
                errors.append(diagnostic)
            if len(errors) == 16:
                break
    return errors
