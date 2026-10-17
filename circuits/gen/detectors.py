"""Structured-PII detectors used by the ZKPriv circuit.

Each pattern is wrapped in non-alphanumeric boundaries (or the virtual
BOUNDARY byte at either end of the text) so "1234-56-7890123" is not an SSN.
Credit cards are matched by length here and filtered by Luhn in the circuit.
"""
from regex_dfa import compile_search_dfa

# left / right context: start-of-text or a byte that cannot extend the token
L_NUM = r"(^|[^0-9A-Za-z])"
R_NUM = r"($|[^0-9A-Za-z])"
L_WORD = r"(^|[^0-9A-Za-z._%+-])"
R_WORD = r"($|[^0-9A-Za-z_-])"
OCTET = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

PATTERNS = {
    # 123-45-6789, 123 45 6789, 123456789 (area 000/666/9xx not excluded: superset is safe)
    "ssn": L_NUM + r"\d{3}[-. ]?\d{2}[-. ]?\d{4}" + R_NUM,
    "email": L_WORD + r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}" + R_WORD,
    # US: (555) 123-4567, 555-123-4567, 555.123.4567, +1 555 123 4567
    "phone_us": L_NUM + r"(\+?1[ .-]?)?(\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}" + R_NUM,
    "ipv4": L_NUM + OCTET + r"\." + OCTET + r"\." + OCTET + r"\." + OCTET + R_NUM,
    # numeric dates: 03/14/1985, 1985-03-14, 14.03.1985
    "date": L_NUM + r"(\d{1,2}[/.-]\d{1,2}[/.-](19|20)\d\d|(19|20)\d\d[/.-]\d{1,2}[/.-]\d{1,2})" + R_NUM,
}


def build_all():
    return {name: compile_search_dfa(p) for name, p in PATTERNS.items()}


if __name__ == "__main__":
    for name, d in build_all().items():
        print(f"{name:10s} states={d.n_states:4d} accept={sorted(d.accept)}")
