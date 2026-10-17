"""Payment-card detector: a 13-19 digit run that passes the Luhn check.

A run is a maximal sequence of digits in which single spaces or hyphens may
separate digits ("4111 1111 1111 1111"). It must start and end at a
non-alphanumeric byte (or the text boundary). The DFA reads left to right and
tracks two Luhn sums, so no lookahead is needed:

    S0 = Luhn sum if the last digit read is the rightmost (not doubled)
    S1 = Luhn sum if the last digit read is doubled
    reading digit d:  S0' = d + S1,  S1' = dbl(d) + S0      (mod 10)

At the end of a run with k digits the run is a card iff 12 <= k <= 19 and
S0 = 0 (mod 10). Known limitation: a card glued to another digit group by a
single separator ("12 4111 1111 1111 1111") merges into one run and is missed.
"""
from regex_dfa import BOUNDARY, DFA

MIN_LEN, MAX_LEN = 12, 19
SEPS = {ord(" "), ord("-")}
ALNUM = set(range(ord("0"), ord("9") + 1)) | set(range(ord("A"), ord("Z") + 1)) | set(range(ord("a"), ord("z") + 1))


def dbl(d: int) -> int:
    x = 2 * d
    return x - 9 if x > 9 else x


def build_card_dfa() -> DFA:
    # symbolic states
    IDLE, WORD, LONG, LONG_SEP, ACCEPT = "idle", "word", "long", "long_sep", "accept"
    ids: dict = {}

    def sid(s):
        if s not in ids:
            ids[s] = len(ids)
        return ids[s]

    for s in (IDLE, WORD, LONG, LONG_SEP, ACCEPT):
        sid(s)
    # run states: ("run", k, S0, S1, after_sep)
    for k in range(1, MAX_LEN + 1):
        for s0 in range(10):
            for s1 in range(10):
                for sep in (0, 1):
                    sid(("run", k, s0, s1, sep))

    def is_card(state) -> bool:
        return state[0] == "run" and MIN_LEN <= state[1] <= MAX_LEN and state[2] == 0

    def end_run(state, byte):
        """The run has ended; byte is the terminating non-digit."""
        if state[4] == 1:
            # "...digits<sep><byte>": the separator already ended the run
            if is_card(state):
                return ACCEPT
            return WORD if byte in ALNUM else IDLE
        if byte in ALNUM:  # glued to letters: not a standalone number
            return WORD
        return ACCEPT if is_card(state) else IDLE

    table: dict = {}
    for s, i in list(ids.items()):
        row = []
        for b in range(256):
            is_digit = 48 <= b <= 57
            d = b - 48
            if s == ACCEPT:
                nxt = ACCEPT
            elif s == IDLE:
                nxt = ("run", 1, d % 10, dbl(d) % 10, 0) if is_digit else (WORD if b in ALNUM else IDLE)
            elif s == WORD:
                nxt = WORD if b in ALNUM else IDLE
            elif s in (LONG, LONG_SEP):
                if is_digit:
                    nxt = LONG
                elif b in SEPS and s == LONG:
                    nxt = LONG_SEP
                else:
                    nxt = WORD if b in ALNUM else IDLE
            else:  # run state
                _, k, s0, s1, sep = s
                if is_digit:
                    nxt = ("run", k + 1, (d + s1) % 10, (dbl(d) + s0) % 10, 0) if k < MAX_LEN else LONG
                elif b in SEPS and sep == 0:
                    nxt = ("run", k, s0, s1, 1)
                else:
                    nxt = end_run(s, b)
            row.append(sid(nxt))
        table[i] = row
    n = len(ids)
    rows = [table[i] for i in range(n)]
    dfa = DFA(n, ids[IDLE], frozenset({ids[ACCEPT]}), rows)
    assert dfa.table[dfa.start][BOUNDARY] == dfa.start  # boundary byte is idle
    from regex_dfa import minimize
    return minimize(dfa)


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        total += dbl(d) if i % 2 else d
    return total % 10 == 0
