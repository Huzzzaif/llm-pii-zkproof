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

def ci(word):
    """Case-insensitive first letter, e.g. [Mm]arch."""
    return f"[{word[0].upper()}{word[0].lower()}]{word[1:]}"


MONTHS = "(" + "|".join(ci(m) for m in [
    "january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
    "november", "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov",
    "dec"]) + ")"
DAY = r"\d{1,2}(st|nd|rd|th)?"
YEAR = r"(19|20)\d\d"

PATTERNS = {
    # 123-45-6789, 123 45 6789, 123456789 (area 000/666/9xx not excluded: superset is safe)
    "ssn": L_NUM + r"\d{3}[-. ]?\d{2}[-. ]?\d{4}" + R_NUM,
    "email": L_WORD + r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}" + R_WORD,
    # US: (555) 123-4567, 555-123-4567, 555.123.4567, +1 555 123 4567
    "phone_us": L_NUM + r"(\+?1[ .-]?)?(\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}" + R_NUM,
    "ipv4": L_NUM + OCTET + r"\." + OCTET + r"\." + OCTET + r"\." + OCTET + R_NUM,
    # numeric dates: 03/14/1985, 1985-03-14, 14.03.1985
    "date": L_NUM + r"(\d{1,2}[/.-]\d{1,2}[/.-](19|20)\d\d|(19|20)\d\d[/.-]\d{1,2}[/.-]\d{1,2})" + R_NUM,
    # written dates: "March 14, 1985", "14th of March 1985", "May/58", ISO date-times "1960-08-01T00:00"
    "date_text": "(" + L_WORD + MONTHS + r"\.? " + DAY + r",? " + YEAR
                 + "|" + L_NUM + DAY + r" (of )?" + MONTHS + r",? " + YEAR
                 + "|" + L_WORD + MONTHS + r"/\d\d" + R_NUM
                 + "|" + L_NUM + YEAR + r"-\d\d-\d\dT\d\d)",
    # date of birth: a numeric or written date preceded (within 20 chars) by a birth cue
    "dob": r"([Bb]orn|[Bb]irth|[Bb]irthday|DOB|D\.O\.B\.?|[Dd]ob)[^\n]{0,20}"
           + r"(\d{1,2}[/.-]\d{1,2}[/.-](19|20)?\d\d|(19|20)\d\d[/.-]\d{1,2}[/.-]\d{1,2}|"
           + MONTHS + r"\.? " + DAY + r",? " + YEAR + "|" + DAY + r" (of )?" + MONTHS + r",? " + YEAR
           + "|" + MONTHS + r"/\d\d)",
    # account / ID numbers: 8+ consecutive digits (bank accounts, ID cards, card numbers failing Luhn)
    "longnum": L_NUM + r"\d{8,}" + R_NUM,
    # prefixed identifiers: passport G34800996, ACCT-8175175160, MRN-315378, licence M0524206
    "id_prefixed": L_NUM + r"[A-Z]{1,4}-?\d{5,}" + R_NUM,
    # IBAN (ISO 13616): country code, check digits, 11-30 alphanumerics
    "iban": L_NUM + r"[A-Z][A-Z]\d\d[A-Z0-9]{11,30}" + R_NUM,
    # obfuscated e-mail: "name AT host DOT com", "name [at] host [dot] com"
    "email_obf": L_WORD + r"[A-Za-z0-9._%+-]+ ?(AT|at|\[at\]|\(at\)) ?[A-Za-z0-9-]+ ?(DOT|dot|\[dot\]|\(dot\)) ?[A-Za-z]{2,}" + R_WORD,
    # international numbers (E.164-style): "+44 7894 302408", "034.5324.2943", "+12-66-414-3121"
    "phone_intl": L_NUM + r"(\+\d{1,4}[ .-]?|0)\d{1,5}([ .-]?\d{2,5}){2,4}" + R_NUM,
}


def build_all():
    return {name: compile_search_dfa(p) for name, p in PATTERNS.items()}


if __name__ == "__main__":
    for name, d in build_all().items():
        print(f"{name:10s} states={d.n_states:4d} accept={sorted(d.accept)}")
