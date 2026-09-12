#!/usr/bin/env python3
"""Rename a C or C++ symbol through clangd, which answers with the AST.

CLAUDE.md: a rename is an AST question and a regex cannot answer it. This
drives clangd over the language server protocol, asks it for the rename,
and writes what it answers.

Usage:
    tools/rename-symbol.py FILE:LINE:COLUMN NEW_NAME
    tools/rename-symbol.py FILE OLD_NAME NEW_NAME

LINE and COLUMN count from 1. The second form finds the first place the
old name stands in the file and asks from there. Read the diff after.
"""
import json
import os
import subprocess
import sys


class Clangd:
    """One clangd process, spoken to over the protocol on its stdin."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.next_id = 1
        self.process = subprocess.Popen(
            ["clangd", "--background-index", "--log=error"],
            cwd=self.root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    def send(self, payload):
        body = json.dumps(payload).encode()
        self.process.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.process.stdin.flush()

    def read(self):
        length = 0
        while True:
            line = self.process.stdout.readline()
            if line in (b"\r\n", b"\n"):
                break
            if not line:
                raise SystemExit("clangd closed its output")
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        return json.loads(self.process.stdout.read(length))

    def wait_until_indexed(self, quiet_seconds=8, cap_seconds=600):
        """clangd renames across files only from its project index, and it
        builds that index in the background. There is no one message that
        says the index is whole, so this waits until clangd has said
        nothing for a while. The index is kept beside the compile database
        in .cache/clangd/index, so only the first run waits long."""
        import select
        import time
        started = time.time()
        while time.time() - started < cap_seconds:
            ready, _, _ = select.select([self.process.stdout], [], [],
                                        quiet_seconds)
            if not ready:
                return
            self.read()

    def ask(self, method, params):
        """One request, and the answer to that request and no other."""
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method,
                   "params": params})
        while True:
            message = self.read()
            if message.get("id") == request_id:
                if "error" in message:
                    raise SystemExit("clangd: %s" % message["error"]["message"])
                return message.get("result")

    def tell(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})


def uri_of(path):
    return "file://" + os.path.abspath(path)


def path_of(uri):
    return uri[len("file://"):]


def apply_edits(edits_by_uri):
    """Write every edit, from the last position in a file to the first, so
    an earlier edit never moves a later one's offsets."""
    touched = []
    for uri, edits in edits_by_uri.items():
        path = path_of(uri)
        lines = open(path, encoding="utf-8").read().split("\n")
        ordered = sorted(
            edits,
            key=lambda e: (e["range"]["start"]["line"],
                           e["range"]["start"]["character"]),
            reverse=True,
        )
        for edit in ordered:
            start = edit["range"]["start"]
            end = edit["range"]["end"]
            if start["line"] != end["line"]:
                raise SystemExit("%s: an edit spans lines, which this tool "
                                 "does not write" % path)
            line = lines[start["line"]]
            lines[start["line"]] = (line[:start["character"]] + edit["newText"]
                                    + line[end["character"]:])
        open(path, "w", encoding="utf-8").write("\n".join(lines))
        touched.append((path, len(edits)))
    return touched


def find_name(path, name):
    """The first place a name stands in a file, as line and column. A
    comment line is skipped: the same word often stands in the sentence
    above a declaration, and clangd finds no symbol there."""
    for number, line in enumerate(open(path, encoding="utf-8"), 1):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*") or \
           stripped.startswith("/*") or stripped.startswith("#"):
            continue
        column = line.find(name)
        while column >= 0:
            before = line[column - 1] if column else " "
            after = line[column + len(name):column + len(name) + 1] or " "
            if not (before.isalnum() or before == "_") and \
               not (after.isalnum() or after == "_"):
                return number, column + 1
            column = line.find(name, column + 1)
    raise SystemExit("%s holds no symbol named %s" % (path, name))


def main(argv):
    if len(argv) == 3 and argv[0].count(":") == 2:
        path, line_text, column_text = argv[0].split(":")
        line, column = int(line_text), int(column_text)
        new_name = argv[1]
        root = argv[2]
    elif len(argv) == 3:
        path, old_name, new_name = argv
        line, column = find_name(path, old_name)
        root = "."
    elif len(argv) == 4:
        path, old_name, new_name, root = argv
        line, column = find_name(path, old_name)
    else:
        raise SystemExit(__doc__)

    clangd = Clangd(root)
    clangd.ask("initialize", {
        "processId": os.getpid(),
        "rootUri": uri_of(root),
        "capabilities": {"workspace": {"workspaceEdit":
                                       {"documentChanges": True}}},
    })
    clangd.tell("initialized", {})
    clangd.wait_until_indexed()
    clangd.tell("textDocument/didOpen", {"textDocument": {
        "uri": uri_of(path), "languageId": "cpp", "version": 1,
        "text": open(path, encoding="utf-8").read(),
    }})
    result = clangd.ask("textDocument/rename", {
        "textDocument": {"uri": uri_of(path)},
        "position": {"line": line - 1, "character": column - 1},
        "newName": new_name,
    })
    if not result:
        raise SystemExit("clangd refused the rename at %s:%d:%d"
                         % (path, line, column))

    edits_by_uri = result.get("changes")
    if edits_by_uri is None:
        edits_by_uri = {change["textDocument"]["uri"]: change["edits"]
                        for change in result.get("documentChanges", [])}
    for touched_path, count in apply_edits(edits_by_uri):
        print("%s: %d occurrence(s)" % (touched_path, count))
    clangd.ask("shutdown", None)
    clangd.tell("exit", {})


if __name__ == "__main__":
    main(sys.argv[1:])
