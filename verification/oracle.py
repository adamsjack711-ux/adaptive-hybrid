#!/usr/bin/env python3
"""Order open Tamarin goals while preserving their original indices."""
import sys

def priority(goal):
    if any(word in goal for word in ("KEM", "Secret", "secret")):
        return 3
    if any(word in goal for word in ("Certificate", "Received", "Holding", "Assembled")):
        return 0
    if any(word in goal for word in ("ed(", "slh(", "Honest", "Eligible")):
        return 1
    return 2

goals = [line.split(":", 1) for line in sys.stdin if ":" in line]
for index, goal in sorted(goals, key=lambda item: priority(item[1])):
    print(index.strip())
