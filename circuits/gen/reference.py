"""Independent reference detectors, written with Python's `re`, used to
differentially test the compiled DFAs (and later the Noir circuit).
They must agree with the DFAs on every input."""
import re

from card_dfa import ALNUM, MAX_LEN, MIN_LEN, luhn_ok
from detectors import PATTERNS


def _to_re(p: str) -> str:
    # our dialect uses ^/$ as the virtual boundary; with re.search over the
    # whole text, ^ and $ already mean text start / end.
    return p


REF = {k: re.compile(_to_re(v).encode()) for k, v in PATTERNS.items()}


def ref_regex(name: str, data: bytes) -> bool:
    return REF[name].search(data) is not None


def ref_card(data: bytes) -> bool:
    """Maximal runs of digits with single space/hyphen separators."""
    i, n = 0, len(data)
    while i < n:
        if not (48 <= data[i] <= 57) or (i > 0 and data[i - 1] in ALNUM):
            i += 1
            continue
        j, digits = i, []
        while j < n:
            if 48 <= data[j] <= 57:
                digits.append(chr(data[j]))
                j += 1
            elif data[j] in (32, 45) and j + 1 < n and 48 <= data[j + 1] <= 57:
                j += 1
            else:
                break
        end_ok = j >= n or data[j] not in ALNUM
        if end_ok and MIN_LEN <= len(digits) <= MAX_LEN and luhn_ok("".join(digits)):
            return True
        i = j if j > i else i + 1
    return False
