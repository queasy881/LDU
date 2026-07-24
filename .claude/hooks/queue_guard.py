#!/usr/bin/env python3
"""Stop hook: refuse to end the turn while the work queue still has items.

The failure this exists to prevent: being told "work the whole queue, do not
stop to report between items", and then stopping after each item anyway to
write a status summary. Judgement demonstrably does not hold across a long
session, so this makes it mechanical -- the turn cannot end while
.claude/queue.md has an unchecked `- [ ]` line.

Exit 0  = allow the stop.
Exit 2  = block it; stderr is fed back as the reason to keep working.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QUEUE = os.path.join(HERE, "..", "queue.md")


def main():
    # A Stop hook already reported as blocking must not loop forever.
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}
    if payload.get("stop_hook_active"):
        return 0

    try:
        text = open(QUEUE, encoding="utf-8").read()
    except OSError:
        return 0  # no queue file -> nothing to enforce

    open_items = re.findall(r"^\s*-\s*\[ \]\s*(.+)$", text, re.M)
    # An item explicitly parked on a user decision is not actionable.
    actionable = [i for i in open_items if "BLOCKED" not in i.upper()]
    if not actionable:
        return 0

    nxt = actionable[0]
    sys.stderr.write(
        f"{len(actionable)} queue item(s) remain in .claude/queue.md. "
        f"Do NOT write a status report. Continue with: {nxt}\n"
        "Tick an item only once it is committed and verified. "
        "If you are genuinely blocked on a user decision, mark that item BLOCKED "
        "with the reason and move to the next one.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
