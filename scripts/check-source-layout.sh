#!/usr/bin/env bash
# SOURCE_LAYOUT.md [V-5]: structural consistency of include/ and src/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

exec python3 - "${ROOT}" << 'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
INCLUDE = ROOT / "include"
SRC = ROOT / "src"
CMAKE = ROOT / "CMakeLists.txt"

errors: list[str] = []


def fail(rule: str, msg: str) -> None:
    errors.append(f"[{rule}] {msg}")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def list_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in suffixes)


IPP_FILES = list_files(INCLUDE, (".ipp",))
HPP_FILES = list_files(INCLUDE, (".hpp", ".h", ".hh", ".hxx"))
CPP_FILES = list_files(SRC, (".cpp", ".cc", ".cxx"))

# Angle or quoted includes; groups 1 and 2 are mutually exclusive.
INCLUDE_RE = re.compile(
    r"^[ \t]*#[ \t]*include[ \t]*(?:<([^>]+)>|\"([^\"]+)\")",
    re.MULTILINE,
)


def include_path(match: re.Match[str]) -> str:
    return (match.group(1) or match.group(2)).strip()


def join_continuations(text: str) -> str:
    lines = text.splitlines()
    joined: list[str] = []
    buf = ""
    for line in lines:
        buf = (buf + " " + line) if buf else line
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            continue
        joined.append(buf)
        buf = ""
    if buf:
        joined.append(buf)
    return "\n".join(joined) + ("\n" if text.endswith("\n") else "")


def iter_includes(text: str) -> list[str]:
    return [include_path(m) for m in INCLUDE_RE.finditer(join_continuations(text))]


def first_include(text: str) -> str | None:
    incs = iter_includes(text)
    return incs[0] if incs else None


def ipp_include_path(ipp: Path) -> str:
    try:
        return ipp.relative_to(INCLUDE).as_posix()
    except ValueError:
        return ipp.as_posix()


def expected_host_hpp(ipp_rel: str) -> str | None:
    if re.fullmatch(r"yanterm-ssh/core/impl/connection_[^/]+\.ipp", ipp_rel):
        return "yanterm-ssh/core/connection.hpp"
    m = re.fullmatch(r"(.+)/impl/([^/]+)\.ipp", ipp_rel)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}.hpp"


def collect_includers(files: list[Path], needle: str) -> list[Path]:
    hits: list[Path] = []
    for path in files:
        text = join_continuations(read_text(path))
        for inc in INCLUDE_RE.finditer(text):
            if include_path(inc) == needle:
                hits.append(path)
                break
    return hits


def strip_comments_and_strings(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i = min(i + 2, n)
            continue
        if ch in "\"'":
            quote = ch
            out.append(" ")
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def scan_ipp_body(ipp: Path, text: str) -> None:
    code = strip_comments_and_strings(text)
    rel = ipp_include_path(ipp)
    if re.search(r"\bnamespace\s*\{", code):
        fail("I-5", f"{rel}: anonymous namespace is forbidden")

    i = 0
    n = len(code)
    stack: list[str] = []
    pending_ns = False
    while i < n:
        ch = code[i]
        if ch.isalpha() or ch == "_":
            m = IDENT.match(code, i)
            assert m is not None
            word = m.group(0)
            nxt = m.end()
            if word == "namespace":
                pending_ns = True
                i = nxt
                continue
            if word == "static":
                rest = code[nxt : nxt + 16]
                if rest.startswith("_cast") or rest.startswith("_assert"):
                    i = nxt
                    continue
                if all(kind == "ns" for kind in stack):
                    fail("I-5", f"{rel}: namespace-scope static is forbidden")
                i = nxt
                continue
            if word == "template":
                j = nxt
                while j < n and code[j].isspace():
                    j += 1
                if j < n and code[j] == "<" and all(kind == "ns" for kind in stack):
                    fail("I-2", f"{rel}: file/namespace-scope template < is forbidden")
                i = nxt
                continue
            i = nxt
            continue
        if ch in ";=":
            pending_ns = False
        elif ch == "{":
            stack.append("ns" if pending_ns else "other")
            pending_ns = False
        elif ch == "}":
            if stack:
                stack.pop()
            pending_ns = False
        i += 1


def has_i3_guard(text: str, ipp_rel: str) -> bool:
    joined = join_continuations(text)
    if not re.search(
        r"#[ \t]*if[ \t]+!defined\s*\(\s*YANTERM_SSH_HEADER_ONLY\s*\)"
        r"\s*&&\s*!defined\s*\(\s*YANTERM_SSH_SOURCE\s*\)",
        joined,
    ):
        return False
    quoted = re.escape(ipp_rel)
    if not re.search(
        r"#[ \t]*error[ \t]+\"[^\"]*" + quoted + r"[^\"]*implementation file",
        joined,
    ):
        return False
    return True


def normalize_if_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def is_header_only_if(expr: str) -> bool:
    return normalize_if_expr(expr) == "defined(YANTERM_SSH_HEADER_ONLY)"


IF_RE = re.compile(r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")


def hpp_ipp_includes_in_header_only(path: Path, text: str) -> None:
    joined = join_continuations(text)
    rel = path.relative_to(ROOT).as_posix()
    stack: list[dict[str, bool]] = []
    for lineno, line in enumerate(joined.splitlines(), 1):
        m = IF_RE.match(line)
        if m:
            kind = m.group(1)
            rest = m.group(2).strip()
            if kind == "if":
                stack.append(
                    {"header_only": is_header_only_if(rest), "true_branch": True}
                )
            elif kind == "ifdef":
                ident = rest.split()[0] if rest else ""
                stack.append(
                    {
                        "header_only": ident == "YANTERM_SSH_HEADER_ONLY",
                        "true_branch": True,
                    }
                )
            elif kind == "ifndef":
                stack.append({"header_only": False, "true_branch": True})
            elif kind == "elif":
                if not stack:
                    fail("H-8", f"{rel}:{lineno}: #elif without #if")
                    continue
                stack[-1]["header_only"] = is_header_only_if(rest)
                stack[-1]["true_branch"] = True
            elif kind == "else":
                if not stack:
                    fail("H-8", f"{rel}:{lineno}: #else without #if")
                    continue
                stack[-1]["true_branch"] = not stack[-1]["true_branch"]
                stack[-1]["header_only"] = False
            elif kind == "endif":
                if not stack:
                    fail("H-8", f"{rel}:{lineno}: #endif without #if")
                    continue
                stack.pop()
            continue
        inc = INCLUDE_RE.match(line)
        if inc and include_path(inc).endswith(".ipp"):
            in_header_only = any(
                frame["header_only"] and frame["true_branch"] for frame in stack
            )
            if not in_header_only:
                fail(
                    "H-8",
                    f"{rel}:{lineno}: #include of {include_path(inc)} "
                    f"is not inside #if defined(YANTERM_SSH_HEADER_ONLY)",
                )


def parse_static_lib_sources() -> set[str]:
    text = read_text(CMAKE)
    m = re.search(
        r"add_library\s*\(\s*yanterm-ssh-static\s+STATIC\s*(.*?)\)",
        text,
        re.DOTALL,
    )
    if not m:
        fail("S-3", "CMakeLists.txt has no add_library(yanterm-ssh-static STATIC ...)")
        return set()
    block = m.group(1)
    if re.search(r"\bfile\s*\(\s*GLOB", block, re.IGNORECASE):
        fail("S-3", "yanterm-ssh-static sources must not use file(GLOB)")
    listed: set[str] = set()
    for raw in block.replace("\n", " ").split():
        tok = raw.strip()
        if tok.endswith(".cpp") or tok.endswith(".cc") or tok.endswith(".cxx"):
            listed.add(tok.replace("\\", "/"))
    return listed


# ---------------------------------------------------------------------------
# [D-3] no headers in src/
# ---------------------------------------------------------------------------
header_exts = {".h", ".hpp", ".hh", ".hxx", ".h++", ".ipp", ".inl"}
for path in sorted(SRC.rglob("*")):
    if path.is_file() and path.suffix.lower() in header_exts:
        fail(
            "D-3",
            f"{path.relative_to(ROOT).as_posix()}: headers are forbidden under src/",
        )

# ---------------------------------------------------------------------------
# [D-10] each .ipp included by exactly one .hpp and one src/*.cpp
# [I-3] first include is host .hpp + misuse guard
# [I-2]/[I-5] no template < / anonymous namespace / ns-scope static
# ---------------------------------------------------------------------------
if not IPP_FILES:
    fail("D-10", "no .ipp files found under include/")

for ipp in IPP_FILES:
    ipp_rel = ipp_include_path(ipp)
    text = read_text(ipp)
    hpp_hits = collect_includers(HPP_FILES, ipp_rel)
    cpp_hits = collect_includers(CPP_FILES, ipp_rel)
    if len(hpp_hits) != 1:
        names = ", ".join(p.relative_to(ROOT).as_posix() for p in hpp_hits) or "(none)"
        fail(
            "D-10",
            f"{ipp_rel} must be included by exactly one .hpp, found {len(hpp_hits)}: {names}",
        )
    if len(cpp_hits) != 1:
        names = ", ".join(p.relative_to(ROOT).as_posix() for p in cpp_hits) or "(none)"
        fail(
            "D-10",
            f"{ipp_rel} must be included by exactly one src/*.cpp, found {len(cpp_hits)}: {names}",
        )

    host = expected_host_hpp(ipp_rel)
    first = first_include(text)
    if host is None:
        fail("I-3", f"{ipp_rel}: cannot derive host .hpp path")
    elif first != host:
        fail(
            "I-3",
            f"{ipp_rel}: first #include is {first!r}, expected host {host!r}",
        )
    if not has_i3_guard(text, ipp_rel):
        fail(
            "I-3",
            f"{ipp_rel}: missing misuse #error guard "
            f"(!defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE))",
        )
    scan_ipp_body(ipp, text)

# ---------------------------------------------------------------------------
# [S-3] every src/*.cpp that includes an .ipp is listed in yanterm-ssh-static
# ---------------------------------------------------------------------------
cmake_srcs = parse_static_lib_sources()
for cpp in CPP_FILES:
    text = read_text(cpp)
    if not any(inc.endswith(".ipp") for inc in iter_includes(text)):
        continue
    rel = cpp.relative_to(ROOT).as_posix()
    alts = {rel, str(Path("src") / cpp.name), cpp.name}
    if cmake_srcs.isdisjoint(alts):
        fail(
            "S-3",
            f"{rel} includes .ipp but is not listed in yanterm-ssh-static sources",
        )

# ---------------------------------------------------------------------------
# [H-8] .hpp #include of .ipp only inside HEADER_ONLY
# ---------------------------------------------------------------------------
for hpp in HPP_FILES:
    hpp_ipp_includes_in_header_only(hpp, read_text(hpp))

if errors:
    print(f"check-source-layout: {len(errors)} violation(s)", file=sys.stderr)
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1)

print(
    f"check-source-layout: ok "
    f"({len(IPP_FILES)} .ipp, {len(HPP_FILES)} headers, {len(CPP_FILES)} src/*.cpp)"
)
PY
