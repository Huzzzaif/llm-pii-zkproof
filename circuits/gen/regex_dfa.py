"""Compile a small regex dialect to a minimized *search* DFA over bytes.

The search DFA recognises Sigma* R: it reaches an accepting state at position i
iff some match of R ends at i. Running it over every byte of a string and never
reaching an accepting state proves R does not occur anywhere in the string.
Accepting states are made absorbing, so "never accepted" is equivalent to
"final state is not accepting" — the circuit only checks the last state.

Supported syntax: literals, escapes (\\d \\D \\. \\- etc.), character classes
[a-z0-9._%+-] and negated [^...], '.', grouping (...), alternation |,
quantifiers ? * + {m} {m,n}. Anchors ^ and $ are written as the virtual
boundary byte 0x00 (BOUNDARY), which the circuit feeds before and after the text.
"""
from __future__ import annotations

import string
from dataclasses import dataclass, field

BOUNDARY = 0  # virtual byte emitted at the start and end of the text
ALL = frozenset(range(256))
DIGITS = frozenset(ord(c) for c in string.digits)


# ---------------------------------------------------------------- parsing

@dataclass
class Node:
    kind: str  # 'set', 'cat', 'alt', 'star', 'eps'
    chars: frozenset = frozenset()
    kids: list = field(default_factory=list)


def _cls_escape(c: str) -> frozenset:
    if c == "d":
        return DIGITS
    if c == "D":
        return ALL - DIGITS - {BOUNDARY}
    if c == "w":
        return frozenset(ord(x) for x in string.ascii_letters + string.digits + "_")
    if c == "s":
        return frozenset(ord(x) for x in " \t\r\n\f\v")
    control = {"n": 10, "t": 9, "r": 13, "f": 12, "v": 11}
    if c in control:
        return frozenset({control[c]})
    return frozenset({ord(c)})


class Parser:
    def __init__(self, src: str):
        self.s, self.i = src, 0

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else None

    def take(self):
        c = self.s[self.i]
        self.i += 1
        return c

    def parse(self) -> Node:
        n = self.alt()
        if self.peek() is not None:
            raise ValueError(f"unexpected {self.peek()!r} at {self.i}")
        return n

    def alt(self) -> Node:
        kids = [self.cat()]
        while self.peek() == "|":
            self.take()
            kids.append(self.cat())
        return kids[0] if len(kids) == 1 else Node("alt", kids=kids)

    def cat(self) -> Node:
        kids = []
        while self.peek() not in (None, "|", ")"):
            kids.append(self.repeat())
        if not kids:
            return Node("eps")
        return kids[0] if len(kids) == 1 else Node("cat", kids=kids)

    def repeat(self) -> Node:
        n = self.atom()
        while self.peek() in ("?", "*", "+", "{"):
            q = self.take()
            if q == "?":
                n = Node("alt", kids=[n, Node("eps")])
            elif q == "*":
                n = Node("star", kids=[n])
            elif q == "+":
                n = Node("cat", kids=[n, Node("star", kids=[n])])
            else:
                j = self.s.index("}", self.i)
                body, self.i = self.s[self.i:j], j + 1
                lo, _, hi = body.partition(",")
                lo = int(lo)
                hi = lo if not _ else (int(hi) if hi else None)
                req = [n] * lo
                if hi is None:
                    opt = [Node("star", kids=[n])]
                else:
                    opt = [Node("alt", kids=[n, Node("eps")])] * (hi - lo)
                parts = req + opt
                n = Node("cat", kids=parts) if parts else Node("eps")
        return n

    def atom(self) -> Node:
        c = self.take()
        if c == "(":
            n = self.alt()
            if self.take() != ")":
                raise ValueError("missing )")
            return n
        if c == "[":
            return Node("set", chars=self.cls())
        if c == ".":
            return Node("set", chars=ALL - {BOUNDARY})
        if c == "^" or c == "$":
            return Node("set", chars=frozenset({BOUNDARY}))
        if c == "\\":
            return Node("set", chars=_cls_escape(self.take()))
        return Node("set", chars=frozenset({ord(c)}))

    def cls(self) -> frozenset:
        neg = self.peek() == "^"
        if neg:
            self.take()
        out: set[int] = set()
        first = True
        while first or self.peek() != "]":
            first = False
            c = self.take()
            if c == "\\":
                out |= _cls_escape(self.take())
                continue
            if self.peek() == "-" and self.s[self.i + 1] != "]":
                self.take()
                hi = self.take()
                out |= set(range(ord(c), ord(hi) + 1))
            else:
                out.add(ord(c))
        self.take()  # ]
        return frozenset(ALL - out - {BOUNDARY}) if neg else frozenset(out)


# ---------------------------------------------------------------- NFA

class NFA:
    def __init__(self):
        self.eps: list[set[int]] = []
        self.edges: list[list[tuple[frozenset, int]]] = []

    def new(self) -> int:
        self.eps.append(set())
        self.edges.append([])
        return len(self.eps) - 1

    def build(self, n: Node) -> tuple[int, int]:
        s, t = self.new(), self.new()
        if n.kind == "set":
            self.edges[s].append((n.chars, t))
        elif n.kind == "eps":
            self.eps[s].add(t)
        elif n.kind == "cat":
            cur = s
            for k in n.kids:
                a, b = self.build(k)
                self.eps[cur].add(a)
                cur = b
            self.eps[cur].add(t)
        elif n.kind == "alt":
            for k in n.kids:
                a, b = self.build(k)
                self.eps[s].add(a)
                self.eps[b].add(t)
        elif n.kind == "star":
            a, b = self.build(n.kids[0])
            self.eps[s] |= {a, t}
            self.eps[b] |= {a, t}
        return s, t

    def closure(self, states) -> frozenset:
        stack, seen = list(states), set(states)
        while stack:
            for nxt in self.eps[stack.pop()]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return frozenset(seen)


# ---------------------------------------------------------------- DFA

@dataclass
class DFA:
    n_states: int
    start: int
    accept: frozenset
    table: list[list[int]]  # table[state][byte] -> state

    def run(self, data: bytes) -> bool:
        """Reference semantics: True iff the pattern occurs (with boundaries)."""
        s = self.table[self.start][BOUNDARY]
        for b in data:
            s = self.table[s][b]
        s = self.table[s][BOUNDARY]
        return s in self.accept


def compile_search_dfa(pattern: str) -> DFA:
    nfa = NFA()
    a, b = nfa.build(Parser(pattern).parse())
    start = nfa.closure({a})
    # Sigma* prefix: the start set is re-injected at every step.
    sets = {start: 0}
    order = [start]
    rows: list[list[int]] = []
    i = 0
    while i < len(order):
        cur = order[i]
        i += 1
        if b in cur:  # accepting: absorb
            rows.append([sets[cur]] * 256)
            continue
        row = []
        for byte in range(256):
            nxt = {t for s in cur for chars, t in nfa.edges[s] if byte in chars}
            nxt = nfa.closure(nxt) | start
            if nxt not in sets:
                sets[nxt] = len(order)
                order.append(nxt)
            row.append(sets[nxt])
        rows.append(row)
    accept = frozenset(sets[s] for s in order if b in s)
    return minimize(DFA(len(order), 0, accept, rows))


def minimize(d: DFA) -> DFA:
    """Moore partition refinement; keeps state 0 as start."""
    part = [0 if s in d.accept else 1 for s in range(d.n_states)]
    while True:
        sig = {}
        new = []
        for s in range(d.n_states):
            key = (part[s], tuple(part[t] for t in d.table[s]))
            new.append(sig.setdefault(key, len(sig)))
        if len(sig) == len(set(part)):
            break
        part = new
    # renumber so the start state is 0
    remap = {part[d.start]: 0}
    for s in range(d.n_states):
        remap.setdefault(part[s], len(remap))
    n = len(remap)
    table = [None] * n
    for s in range(d.n_states):
        table[remap[part[s]]] = [remap[part[t]] for t in d.table[s]]
    accept = frozenset(remap[part[s]] for s in d.accept)
    return DFA(n, 0, accept, table)
