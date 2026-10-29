from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from dataclasses import dataclass


# -------------------------------------------------------------------------------------------------
# Definitions
# -------------------------------------------------------------------------------------------------


# Resolve the workspace root at startup so the server fails immediately if the bind mount is
# missing
ROOT = Path(os.getenv("PEEK_ROOT", "/workspace")).resolve(strict=True)


# Bounds keep accidental broad requests from producing excessive filesystem work
MAX_FILE_BYTES = 1_000_000_000
MAX_LIST_DEPTH = 5
MAX_LIST_ENTRIES = 500
MAX_SEARCH_RESULTS = 50
MAX_READ_LINES = 400
MAX_LINE_CHARS = 500


# Defense-in-depth checks
DENY_DIRECTORIES = (
    "secrets",
)

DENY_PATTERNS = (
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
)


@dataclass
class FileEntry:
    path: str
    kind: Literal["file", "directory", "symlink"]


@dataclass
class ListFilesResult:
    path: str
    entries: list[FileEntry]
    truncated: bool


@dataclass
class SourceLine:
    line: int
    text: str
    text_truncated: bool


@dataclass
class ReadFileResult:
    path: str
    lines: list[SourceLine]


@dataclass
class SearchMatch:
    path: str
    line: int
    text: str
    text_truncated: bool


@dataclass
class SearchTextResult:
    matches: list[SearchMatch]
    truncated: bool


# These are hints to MCP clients, not security controls. Filesystem isolation comes from path
# validation, the deny list, and the read-only container mount
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,          # Tool is read-only
    openWorldHint=False,        # Tool doesn't interact with external systems or public internet
)


mcp = MCPServer(
    "Peek",
    instructions=(
        "Read-only access to a mounted source tree. "
        "Prefer narrow reads and searches."
    ),
)


# -------------------------------------------------------------------------------------------------
# Internal Functions
# -------------------------------------------------------------------------------------------------


def _relative(path: Path) -> Path:
    """Return a path relative to the workspace root."""
    return path.relative_to(ROOT)


def _is_denied(path: Path) -> bool:
    """Return True if a relative path matches the deny list."""
    return (
        any(part in DENY_DIRECTORIES for part in path.parts)
        or any(path.match(pattern) for pattern in DENY_PATTERNS)
    )


def _resolve(user_path: str) -> Path:
    """Resolve a project-relative path without allowing escape from ROOT."""
    if not user_path or "\0" in user_path:
        raise ValueError("path must be non-empty")

    relative_path = Path(user_path)

    # Reject direct attempts to address files outside the workspace
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("path must be relative and may not contain '..'")

    if _is_denied(relative_path):
        raise PermissionError(f"access denied: {relative_path}")

    # resolve() follows symlinks. We can verify that the final target still resides beneath ROOT,
    # preventing workspace symlink escaping into another part of the container filesystem
    resolved_path = (ROOT / relative_path).resolve(strict=True)

    try:
        resolved_relative = _relative(resolved_path)
    except ValueError:
        raise ValueError("path escapes the workspace") from None

    # Check again after resolving in case of a symlink pointing into a denied directory or file
    if _is_denied(resolved_relative):
        raise PermissionError(f"access denied: {resolved_relative}")

    return resolved_path


def _display(path: Path) -> str:
    """Return a project-relative POSIX path for tool output."""
    return _relative(path).as_posix()


def _is_binary(path: Path) -> bool:
    """Return True if the file is probably binary."""
    # A NUL byte in the first 4 KiB is a cheap and decent binary-file heuristic
    with path.open("rb") as file:
        return b"\0" in file.read(4096)


# -------------------------------------------------------------------------------------------------
# MCP Tools
# -------------------------------------------------------------------------------------------------


@mcp.tool(annotations=READ_ONLY, structured_output=True)
def list_files(
    path: str = ".",
    max_depth: int = 2,
    limit: int = 200,
) -> ListFilesResult:
    """List files and directories below a project-relative path.

    Results are bounded and recursive traversal does not follow directory symlinks.
    """
    base_dir = _resolve(path)

    if not base_dir.is_dir():
        raise ValueError(f"not a directory: {_display(base_dir)}")

    if not 0 <= max_depth <= MAX_LIST_DEPTH:
        raise ValueError(f"max_depth must be between 0 and {MAX_LIST_DEPTH}")

    if not 1 <= limit <= MAX_LIST_ENTRIES:
        raise ValueError(f"limit must be between 1 and {MAX_LIST_ENTRIES}")

    entries: list[FileEntry] = []

    # Recursively traverse directory without following directory symlinks
    for current, directories, files in base_dir.walk(follow_symlinks=False):
        depth = len(current.relative_to(base_dir).parts)

        # Path.walk() uses this list to decide which directories to visit next
        # Modifying it in place prevents descent into denied directories
        directories[:] = sorted(
            name
            for name in directories
            if not _is_denied(_relative(current / name))
        )

        if depth >= max_depth:
            directories.clear()

        if current != base_dir:
            entries.append(FileEntry(path=_display(current), kind="directory"))

            if len(entries) > limit:
                return ListFilesResult(
                    path=_display(base_dir),
                    entries=entries[:limit],
                    truncated=True,
                )

        for name in sorted(files):
            child = current / name
            relative_path = _relative(child)

            if _is_denied(relative_path):
                continue

            entries.append(
                FileEntry(
                    path=relative_path.as_posix(),
                    kind="symlink" if child.is_symlink() else "file",
                )
            )

            if len(entries) > limit:
                return ListFilesResult(
                    path=_display(base_dir),
                    entries=entries[:limit],
                    truncated=True,
                )

    return ListFilesResult(
        path=_display(base_dir),
        entries=entries,
        truncated=False,
    )


@mcp.tool(annotations=READ_ONLY, structured_output=True)
def read_file(
    path: str,
    start_line: int = 1,
    end_line: int = 200,
) -> ReadFileResult:
    """Read a project-relative text file with line numbers."""
    target = _resolve(path)

    if not target.is_file():
        raise ValueError(f"not a file: {_display(target)}")

    if target.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds maximum size of {MAX_FILE_BYTES} bytes")

    if start_line < 1:
        raise ValueError("start_line must be at least 1")

    if end_line < start_line:
        raise ValueError("end_line must be >= start_line")

    if end_line - start_line + 1 > MAX_READ_LINES:
        raise ValueError(f"a read may contain at most {MAX_READ_LINES} lines")

    if _is_binary(target):
        raise ValueError("binary files are not supported")

    output_lines: list[SourceLine] = []

    # `with` guarantees that the file is closed even if reading raises an exception
    with target.open("r", encoding="utf-8", errors="replace") as file:
        for line_number, line in enumerate(file, start=1):

            if line_number < start_line:
                continue

            if line_number > end_line:
                break

            # Remove only the newline, other trailing whitespace is preserved because it may be 
            # meaningful when inspecting source code
            text = line.rstrip("\n")
            text_truncated = len(text) > MAX_LINE_CHARS

            output_lines.append(
                SourceLine(
                    line=line_number,
                    text=text[:MAX_LINE_CHARS],
                    text_truncated=text_truncated,
                )
            )

    return ReadFileResult(path=_display(target), lines=output_lines)


@mcp.tool(annotations=READ_ONLY, structured_output=True)
def search_text(
    query: str,
    path: str = ".",
    file_glob: str = "*",
    case_sensitive: bool = False,
    max_results: int = 20,
) -> SearchTextResult:
    """Search text files for a literal string.

    Search is recursive, bounded by file size and result count, and does not follow directory
    symlinks.
    """
    if not query:
        raise ValueError("query must be non-empty")

    if not 1 <= max_results <= MAX_SEARCH_RESULTS:
        raise ValueError(f"max_results must be between 1 and {MAX_SEARCH_RESULTS}")

    base_dir = _resolve(path)

    if not base_dir.is_dir():
        raise ValueError(f"not a directory: {_display(base_dir)}")

    needle = query if case_sensitive else query.casefold()
    matches: list[SearchMatch] = []

    for current, directories, files in base_dir.walk(follow_symlinks=False):

        # Prevent traversal into denied directories
        directories[:] = sorted(
            name
            for name in directories
            if not _is_denied(_relative(current / name))
        )

        for name in sorted(files):
            relative_path = _relative(current / name)

            if _is_denied(relative_path):
                continue

            if not relative_path.match(file_glob):
                continue

            try:
                # Path.walk() does not follow directory symlinks, but symlinks themselves still
                # appear as file entries. Resolve each candidate through the security boundary
                # before reading it so file symlinks cannot escape ROOT
                target = _resolve(relative_path.as_posix())

                if not target.is_file():
                    continue

                if target.stat().st_size > MAX_FILE_BYTES:
                    continue

                if _is_binary(target):
                    continue

                with target.open("r", encoding="utf-8", errors="replace") as file:
                    for line_number, line in enumerate(file, start=1):
                        haystack = (line if case_sensitive else line.casefold())

                        if needle not in haystack:
                            continue

                        text = line.rstrip("\n")
                        text_truncated = len(text) > MAX_LINE_CHARS

                        matches.append(
                            SearchMatch(
                                path=relative_path.as_posix(),
                                line=line_number,
                                text=text[:MAX_LINE_CHARS],
                                text_truncated=text_truncated,
                            )
                        )

                        if len(matches) > max_results:
                            return SearchTextResult(
                                matches=matches[:max_results],
                                truncated=True,
                            )

            except (OSError, ValueError):
                # A recursively searched file may disappear, become inaccessible, or resolve to
                # somewhere Peek refuses to access. Skip that candidate rather than failing the 
                # whole search
                continue

    return SearchTextResult(matches=matches, truncated=False)


# -------------------------------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------------------------------


def main() -> None:
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        stateless_http=True,
        json_response=True,
    )
