"""
Faker-based synthetic PII corpus generator for ZKPriv evaluation.

Produces 500 realistic multi-domain LLM responses with injected PII across
healthcare, financial, legal, and enterprise domains. Novel PII formats are
intentionally included to stress-test the regex classifier.
"""

import json
import random
import re
from pathlib import Path

from faker import Faker

fake = Faker()
Faker.seed(2027)
random.seed(2027)

# ── PII injection helpers ────────────────────────────────────────────────────

def gen_ssn(style="standard"):
    a, b, c = random.randint(100,999), random.randint(10,99), random.randint(1000,9999)
    if style == "standard":   return f"{a:03d}-{b:02d}-{c:04d}"
    if style == "dots":       return f"{a:03d}.{b:02d}.{c:04d}"
    if style == "spaces":     return f"{a:03d} {b:02d} {c:04d}"
    if style == "nohyphen":   return f"{a:03d}{b:02d}{c:04d}"
    return f"{a:03d}-{b:02d}-{c:04d}"

def gen_phone(style="standard"):
    area = random.randint(200, 999)
    exch = random.randint(200, 999)
    num  = random.randint(1000, 9999)
    if style == "standard":   return f"({area}) {exch}-{num}"
    if style == "dashes":     return f"{area}-{exch}-{num}"
    if style == "dots":       return f"{area}.{exch}.{num}"
    if style == "intl":       return f"+1-{area}-{exch}-{num}"
    if style == "uk":         return f"+44 7{random.randint(100,999)} {random.randint(100,999)}{random.randint(100,999)}"
    if style == "plain":      return f"{area}{exch}{num}"
    return f"({area}) {exch}-{num}"

def gen_email(style="standard"):
    user = fake.user_name()
    domain = random.choice(["gmail.com","yahoo.com","hospital.org","corp.com","lawfirm.net"])
    if style == "standard":  return f"{user}@{domain}"
    if style == "spoken":    return f"{user} AT {domain.replace('.', ' DOT ')}"
    if style == "brackets":  return f"[{user}@{domain}]"
    if style == "parens":    return f"({user}@{domain})"
    return f"{user}@{domain}"

def gen_dob(style="us"):
    d = fake.date_of_birth(minimum_age=18, maximum_age=90)
    if style == "us":        return d.strftime("%m/%d/%Y")
    if style == "eu":        return d.strftime("%d/%m/%Y")
    if style == "iso":       return d.strftime("%Y-%m-%d")
    if style == "natural":
        months = ["January","February","March","April","May","June",
                  "July","August","September","October","November","December"]
        ordinals = {1:"1st",2:"2nd",3:"3rd",**{i:f"{i}th" for i in range(4,32)}}
        return f"born on the {ordinals[d.day]} of {months[d.month-1]} {d.year}"
    if style == "text":
        months = ["January","February","March","April","May","June",
                  "July","August","September","October","November","December"]
        return f"{months[d.month-1]} {d.day}, {d.year}"
    return d.strftime("%m/%d/%Y")

def gen_mrn():
    return f"MRN-{random.randint(100000,999999)}"

def gen_credit_card():
    return fake.credit_card_number(card_type=None)

def gen_ip():
    return fake.ipv4_private() if random.random() < 0.3 else fake.ipv4_public()

def gen_name(style="full"):
    first = fake.first_name()
    last  = fake.last_name()
    if style == "full":      return f"{first} {last}"
    if style == "titled":    return f"{random.choice(['Dr.','Mr.','Ms.','Mrs.'])} {first} {last}"
    if style == "last_first":return f"{last}, {first}"
    return f"{first} {last}"

def gen_passport():
    return f"{random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ')}{random.randint(10000000,99999999)}"

def gen_account_no():
    return f"ACCT-{random.randint(1000000000,9999999999)}"

def gen_iban():
    return f"GB{random.randint(10,99)}BARC{random.randint(10000000,99999999)}{random.randint(10000000,99999999)}"

# ── Domain response templates ────────────────────────────────────────────────

HEALTHCARE_TEMPLATES = [
    lambda p: (
        f"Patient {p['name']} (DOB: {p['dob']}, MRN: {p['mrn']}) was admitted on "
        f"{fake.date_this_year().strftime('%B %d, %Y')} with a chief complaint of chest pain. "
        f"The attending physician contacted the patient at {p['phone']} to confirm the appointment. "
        f"Insurance records are linked to SSN {p['ssn']}. The care team will follow up via "
        f"email at {p['email']}.",
        [p['name'], p['dob'], p['mrn'], p['phone'], p['ssn'], p['email']]
    ),
    lambda p: (
        f"Lab results for {p['name']} (MRN: {p['mrn']}) have been finalized. Patient's date of birth "
        f"is {p['dob']}. Results were sent to {p['email']}. Billing will be charged to the card "
        f"ending in {p['cc'][-4:]}. Contact {p['phone']} for questions.",
        [p['name'], p['mrn'], p['dob'], p['email'], p['phone']]
    ),
    lambda p: (
        f"Discharge summary: {p['name']}, {p['dob']}, admitted under {p['mrn']}. "
        f"Prescription details forwarded to pharmacy. Emergency contact: {p['phone']}. "
        f"Social security on file: {p['ssn']}.",
        [p['name'], p['dob'], p['mrn'], p['phone'], p['ssn']]
    ),
    lambda p: (
        f"Referral request initiated for patient {p['name']}. Primary care provider reached "
        f"at {p['email']}. Patient SSN: {p['ssn']}. Next appointment scheduled; confirmation "
        f"sent to {p['phone']}.",
        [p['name'], p['email'], p['ssn'], p['phone']]
    ),
    lambda p: (
        f"The electronic health record for {p['name']} shows date of birth {p['dob']} and "
        f"medical record number {p['mrn']}. The patient's IP address at time of portal login was "
        f"{p['ip']}. Please verify identity before disclosing further details.",
        [p['name'], p['dob'], p['mrn'], p['ip']]
    ),
]

FINANCIAL_TEMPLATES = [
    lambda p: (
        f"Account holder {p['name']} (SSN: {p['ssn']}) has requested a wire transfer. "
        f"Account number on file: {p['acct']}. Please call {p['phone']} to confirm. "
        f"Transaction receipt will be emailed to {p['email']}.",
        [p['name'], p['ssn'], p['acct'], p['phone'], p['email']]
    ),
    lambda p: (
        f"Credit application submitted by {p['name']}, born {p['dob']}. Card number provided: "
        f"{p['cc']}. Social security number: {p['ssn']}. Correspondence to {p['email']}.",
        [p['name'], p['dob'], p['cc'], p['ssn'], p['email']]
    ),
    lambda p: (
        f"Dear {p['name']}, your account {p['acct']} shows unusual activity. We attempted to "
        f"reach you at {p['phone']} and {p['email']}. IBAN on international transfers: {p['iban']}.",
        [p['name'], p['acct'], p['phone'], p['email'], p['iban']]
    ),
    lambda p: (
        f"Loan approval for {p['name']} (SSN {p['ssn']}). Disbursement to account {p['acct']}. "
        f"Notification sent to {p['email']} and {p['phone']}. Passport verified: {p['passport']}.",
        [p['name'], p['ssn'], p['acct'], p['email'], p['phone'], p['passport']]
    ),
    lambda p: (
        f"Tax filing initiated for {p['name']}, TIN matches SSN {p['ssn']}. Date of birth: "
        f"{p['dob']}. Refund to {p['acct']}. IRS correspondence to {p['email']}.",
        [p['name'], p['ssn'], p['dob'], p['acct'], p['email']]
    ),
]

LEGAL_TEMPLATES = [
    lambda p: (
        f"In the matter of {p['name']} v. State, the defendant (DOB: {p['dob']}, SSN: {p['ssn']}) "
        f"has retained counsel. Contact counsel at {p['email']} or {p['phone']}. "
        f"Passport number {p['passport']} was submitted as identification.",
        [p['name'], p['dob'], p['ssn'], p['email'], p['phone'], p['passport']]
    ),
    lambda p: (
        f"Client intake form completed for {p['name']}. Social security: {p['ssn']}. "
        f"Reachable at {p['phone']} and {p['email']}. Date of birth on record: {p['dob']}.",
        [p['name'], p['ssn'], p['phone'], p['email'], p['dob']]
    ),
    lambda p: (
        f"Deposition scheduled for {p['name']} on {fake.future_date().strftime('%B %d, %Y')}. "
        f"Witness to be served at {p['email']}. Identity confirmed via passport {p['passport']}. "
        f"Emergency phone: {p['phone']}.",
        [p['name'], p['email'], p['passport'], p['phone']]
    ),
    lambda p: (
        f"Exhibit A: Communications from {p['email']} originating at IP {p['ip']} confirm "
        f"that {p['name']} (SSN: {p['ssn']}) was present at the location on the date in question.",
        [p['email'], p['ip'], p['name'], p['ssn']]
    ),
    lambda p: (
        f"Settlement agreement between {p['name']} and defendant. Funds transferred to IBAN "
        f"{p['iban']}. Client contacted at {p['phone']}. Tax identification: {p['ssn']}.",
        [p['name'], p['iban'], p['phone'], p['ssn']]
    ),
]

ENTERPRISE_TEMPLATES = [
    lambda p: (
        f"Employee record updated for {p['name']}. Work email: {p['email']}. Direct line: "
        f"{p['phone']}. Payroll linked to SSN {p['ssn']}. System access from IP {p['ip']}.",
        [p['name'], p['email'], p['phone'], p['ssn'], p['ip']]
    ),
    lambda p: (
        f"IT security alert: login attempt for {p['email']} from {p['ip']} at "
        f"{fake.time()}. Account {p['acct']} flagged. Contact HR at {p['phone']}.",
        [p['email'], p['ip'], p['acct'], p['phone']]
    ),
    lambda p: (
        f"Onboarding checklist for {p['name']} (start date: {fake.future_date().strftime('%B %d, %Y')}). "
        f"SSN for I-9: {p['ssn']}. Direct deposit to account {p['acct']}. "
        f"Confirmation to {p['email']}.",
        [p['name'], p['ssn'], p['acct'], p['email']]
    ),
    lambda p: (
        f"Performance review submitted for {p['name']}. Manager contacted {p['email']} and "
        f"called {p['phone']}. Employee DOB: {p['dob']}. Badge access log IP: {p['ip']}.",
        [p['name'], p['email'], p['phone'], p['dob'], p['ip']]
    ),
    lambda p: (
        f"Expense report from {p['name']} submitted. Reimbursement card: {p['cc']}. "
        f"Approval email to {p['email']}. Travel passport: {p['passport']}.",
        [p['name'], p['cc'], p['email'], p['passport']]
    ),
]

DOMAIN_TEMPLATES = {
    "healthcare":  HEALTHCARE_TEMPLATES,
    "financial":   FINANCIAL_TEMPLATES,
    "legal":       LEGAL_TEMPLATES,
    "enterprise":  ENTERPRISE_TEMPLATES,
}

# Mix of PII format styles — some novel to stress the classifier
SSN_STYLES   = ["standard","standard","standard","dots","spaces","nohyphen"]
PHONE_STYLES = ["standard","standard","dashes","dots","intl","uk","plain"]
EMAIL_STYLES = ["standard","standard","standard","spoken","brackets"]
DOB_STYLES   = ["us","us","eu","iso","natural","text"]
NAME_STYLES  = ["full","full","titled","last_first"]

def make_pii_payload():
    return {
        "name":     gen_name(random.choice(NAME_STYLES)),
        "ssn":      gen_ssn(random.choice(SSN_STYLES)),
        "phone":    gen_phone(random.choice(PHONE_STYLES)),
        "email":    gen_email(random.choice(EMAIL_STYLES)),
        "dob":      gen_dob(random.choice(DOB_STYLES)),
        "mrn":      gen_mrn(),
        "cc":       gen_credit_card(),
        "ip":       gen_ip(),
        "passport": gen_passport(),
        "acct":     gen_account_no(),
        "iban":     gen_iban(),
    }

def generate_corpus(n: int = 500) -> list[dict]:
    domains = list(DOMAIN_TEMPLATES.keys())
    per_domain = n // len(domains)
    records = []
    idx = 0

    for domain in domains:
        templates = DOMAIN_TEMPLATES[domain]
        for i in range(per_domain):
            pii = make_pii_payload()
            tmpl = templates[i % len(templates)]
            text, pii_values = tmpl(pii)
            records.append({
                "id":         idx,
                "domain":     domain,
                "text":       text,
                "pii_present": True,
                "pii_values": pii_values,
                "pii_payload": pii,
            })
            idx += 1

    # Fill remainder with mixed domain
    while len(records) < n:
        domain = random.choice(domains)
        pii = make_pii_payload()
        tmpl = random.choice(DOMAIN_TEMPLATES[domain])
        text, pii_values = tmpl(pii)
        records.append({
            "id":         idx,
            "domain":     domain,
            "text":       text,
            "pii_present": True,
            "pii_values": pii_values,
            "pii_payload": pii,
        })
        idx += 1

    random.shuffle(records)
    for i, r in enumerate(records):
        r["id"] = i
    return records


if __name__ == "__main__":
    out_path = Path(__file__).parent / "synth_test_500.json"
    corpus = generate_corpus(500)
    with open(out_path, "w") as f:
        json.dump(corpus, f, indent=2)
    print(f"Generated {len(corpus)} records → {out_path}")
    domain_counts = {}
    for r in corpus:
        domain_counts[r["domain"]] = domain_counts.get(r["domain"], 0) + 1
    for d, c in sorted(domain_counts.items()):
        print(f"  {d}: {c}")
