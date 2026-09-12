#!/usr/bin/env python3
"""Rename many C or C++ symbols through one clangd session.

CLAUDE.md: a rename is an AST question and a regex cannot answer it.
tools/rename-symbol.py asks one question per clangd process, which costs
a preamble build each time. This asks them all of one process.

Reads one rename per line on standard input:

    FILE:LINE:COLUMN NEW_NAME

LINE and COLUMN count from 1, and they are read against the file as it
stands now. So give the renames for one file from its last line to its
first: a rename rewrites only the lines that carry the symbol, and
working upward keeps every later position true.

Every file clangd edits is written to disk and re-opened, so the next
question sees what the last answer wrote. Read the diff after.
"""
import json
import os
import select
import subprocess
import sys


class Clangd:
    """One clangd process, and what it has been told about each file."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.next_id = 1
        self.versions = {}
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

    def ask(self, method, params):
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method,
                   "params": params})
        while True:
            message = self.read()
            if message.get("id") == request_id:
                if "error" in message:
                    return {"__error__": message["error"]["message"]}
                return message.get("result")

    def tell(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def wait_until_quiet(self, seconds=8, cap=900):
        import time
        started = time.time()
        while time.time() - started < cap:
            ready, _, _ = select.select([self.process.stdout], [], [], seconds)
            if not ready:
                return
            self.read()

    def open_file(self, path):
        """Tell clangd what a file holds now, or that it changed."""
        text = open(path, encoding="utf-8").read()
        uri = "file://" + os.path.abspath(path)
        if uri in self.versions:
            self.versions[uri] += 1
            self.tell("textDocument/didChange", {
                "textDocument": {"uri": uri, "version": self.versions[uri]},
                "contentChanges": [{"text": text}],
            })
        else:
            self.versions[uri] = 1
            self.tell("textDocument/didOpen", {"textDocument": {
                "uri": uri, "languageId": "cpp", "version": 1, "text": text}})
        return uri


def apply_edits(edits_by_uri):
    """Write every edit, last position first, so an earlier edit never
    moves a later one."""
    touched = []
    for uri, edits in edits_by_uri.items():
        path = uri[len("file://"):]
        lines = open(path, encoding="utf-8").read().split("\n")
        for edit in sorted(edits,
                           key=lambda one: (one["range"]["start"]["line"],
                                            one["range"]["start"]["character"]),
                           reverse=True):
            start = edit["range"]["start"]
            end = edit["range"]["end"]
            if start["line"] != end["line"]:
                raise SystemExit("%s: an edit spans lines" % path)
            line = lines[start["line"]]
            lines[start["line"]] = (line[:start["character"]] + edit["newText"]
                                    + line[end["character"]:])
        open(path, "w", encoding="utf-8").write("\n".join(lines))
        touched.append(path)
    return touched


def main(root):
    renames = []
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        where, new_name = line.split()
        path, line_text, column_text = where.rsplit(":", 2)
        renames.append((path, int(line_text), int(column_text), new_name))

    clangd = Clangd(root)
    clangd.ask("initialize", {
        "processId": os.getpid(),
        "rootUri": "file://" + os.path.abspath(root),
        "capabilities": {"workspace": {"workspaceEdit": {"documentChanges": True}}},
    })
    clangd.tell("initialized", {})
    clangd.wait_until_quiet()

    done = refused = 0
    for path, line, column, new_name in renames:
        uri = clangd.open_file(path)
        result = clangd.ask("textDocument/rename", {
            "textDocument": {"uri": uri},
            "position": {"line": line - 1, "character": column - 1},
            "newName": new_name,
        })
        if not result or "__error__" in result:
            refused += 1
            print("REFUSED %s:%d:%d -> %s" % (path, line, column, new_name),
                  flush=True)
            continue
        edits = result.get("changes")
        if edits is None:
            edits = {change["textDocument"]["uri"]: change["edits"]
                     for change in result.get("documentChanges", [])}
        for written in apply_edits(edits):
            if "file://" + os.path.abspath(written) in clangd.versions:
                clangd.open_file(written)
        done += 1
        print(".", end="", flush=True)
    print("\n%d renamed, %d refused" % (done, refused))
    clangd.ask("shutdown", None)
    clangd.tell("exit", {})


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
