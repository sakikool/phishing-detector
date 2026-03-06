import re

# ─────────────────────────────────────────────
#  PHISHING RULES
#  Each rule has a label, a score weight, and
#  a list of regex patterns to check against.
# ─────────────────────────────────────────────

RULES = {
    "urgency": {
        "label": "Urgency / Pressure Language",
        "weight": 25,
        "patterns": [
            r"urgent|immediately|act now|expires|limited time|24 hours|within \d+ hours",
            r"your account (will be|has been) (suspended|terminated|closed|locked)",
            r"verify (immediately|now|today|your account)",
            r"respond (immediately|asap|urgently|within)",
        ],
    },
    "threats": {
        "label": "Threats & Fear Tactics",
        "weight": 30,
        "patterns": [
            r"will be (deleted|suspended|terminated|disabled|closed)",
            r"unauthorized access|suspicious (activity|login|sign.?in)",
            r"security (alert|warning|breach|issue|threat)",
            r"your (account|password|information) (has been|was) (compromised|hacked|stolen)",
        ],
    },
    "links": {
        "label": "Suspicious Link / Click Requests",
        "weight": 20,
        "patterns": [
            r"click (here|this link|below)",
            r"confirm your (account|password|email|identity|details|information)",
            r"update your (billing|payment|account|credit card) (information|details)",
            r"login to (verify|confirm|update|access)",
        ],
    },
    "sensitive": {
        "label": "Requests for Sensitive Info",
        "weight": 30,
        "patterns": [
            r"social security|ssn|date of birth|mother'?s maiden",
            r"credit card|bank account|routing number|pin number",
            r"password|username|login credentials",
            r"provide your (full name|address|phone|email|information)",
        ],
    },
    "spoofing": {
        "label": "Spoofing / Impersonation",
        "weight": 20,
        "patterns": [
            r"paypal|amazon|apple|microsoft|google|irs|fedex|ups|netflix|bank of america|chase|wells fargo",
            r"dear (customer|user|member|account holder|valued)",
            r"official (notice|notification|communication|message)",
            r"your (apple id|google account|microsoft account|paypal account)",
        ],
    },
    "grammar": {
        "label": "Poor Grammar / Spelling Signals",
        "weight": 15,
        "patterns": [
            r"kindly (click|provide|confirm|update|verify)",
            r"do the needful|revert back to us",
            r"\b(recieve|adress|occured|wierd|definately)\b",
        ],
    },
}


# ─────────────────────────────────────────────
#  ANALYZE FUNCTION
# ─────────────────────────────────────────────

def analyze_email(text: str) -> dict:
    """Analyze email text and return a risk report."""
    findings = []
    total_score = 0

    for key, rule in RULES.items():
        matched = any(re.search(p, text, re.IGNORECASE) for p in rule["patterns"])
        if matched:
            findings.append({"key": key, "label": rule["label"], "weight": rule["weight"]})
            total_score += rule["weight"]

    score = min(100, total_score)

    if score >= 60:
        verdict = "🚨 HIGH RISK — Likely Phishing"
    elif score >= 30:
        verdict = "⚠️  SUSPICIOUS — Proceed with Caution"
    elif score >= 10:
        verdict = "🔍 LOW RISK — Minor Concerns"
    else:
        verdict = "✅ LIKELY SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


# ─────────────────────────────────────────────
#  DISPLAY RESULTS
# ─────────────────────────────────────────────

def print_results(result: dict):
    width = 55
    print("\n" + "═" * width)
    print("  PHISHGUARD — EMAIL THREAT DETECTOR")
    print("═" * width)

    print(f"\n  {result['verdict']}")
    print(f"  Threat Score: {result['score']}/100")

    # Visual score bar
    filled = int(result["score"] / 100 * 40)
    bar = "█" * filled + "░" * (40 - filled)
    print(f"\n  [{bar}]")
    print(f"   SAFE {'':>15} SUSPICIOUS {'':>5} DANGER")

    print(f"\n{'─' * width}")
    print(f"  THREAT INDICATORS FOUND: {len(result['findings'])}")
    print(f"{'─' * width}")

    if not result["findings"]:
        print("\n  ✓ No known phishing patterns detected.")
        print("    Always stay cautious with unexpected emails.\n")
    else:
        for f in result["findings"]:
            print(f"\n  ⚑  {f['label']}")
            print(f"     Score contribution: +{f['weight']} pts")

    print(f"\n{'─' * width}")
    print("  SAFETY TIPS")
    print(f"{'─' * width}")
    tips = [
        "Never click links in suspicious emails",
        "Legit companies never ask for passwords via email",
        "Check the actual sender address, not just the name",
        "When in doubt, go directly to the company's website",
    ]
    for tip in tips:
        print(f"  → {tip}")

    print("\n" + "═" * width + "\n")


# ─────────────────────────────────────────────
#  MAIN — interactive loop
# ─────────────────────────────────────────────

EXAMPLE_PHISHING = """
Dear Valued Customer,

We have detected suspicious activity on your PayPal account.
Your account will be suspended within 24 hours unless you verify
your information immediately.

Click here to confirm your account and update your billing
information now to avoid termination.

Please provide your full name, credit card number, and password
to restore access.

Act now — this is an urgent security alert.

PayPal Security Team
"""

EXAMPLE_SAFE = """
Hi Sarah,

Just following up on our meeting from Tuesday. I've attached
the Q3 report you requested.

Let me know if you have any questions or want to schedule
a call to go through the numbers together.

Best,
Mike
"""


def main():
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║         PHISHGUARD — Python Email Detector          ║")
    print("╚══════════════════════════════════════════════════════╝")
    print("\nOptions:")
    print("  1 - Load phishing example")
    print("  2 - Load safe email example")
    print("  3 - Paste your own email")
    print("  q - Quit\n")

    while True:
        choice = input("Choose an option (1/2/3/q): ").strip().lower()

        if choice == "q":
            print("\nGoodbye!\n")
            break

        elif choice == "1":
            email_text = EXAMPLE_PHISHING
            print("\n[Loaded phishing example]")

        elif choice == "2":
            email_text = EXAMPLE_SAFE
            print("\n[Loaded safe email example]")

        elif choice == "3":
            print("\nPaste your email below.")
            print("When done, type END on a new line and press Enter:\n")
            lines = []
            while True:
                line = input()
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            email_text = "\n".join(lines)

        else:
            print("Invalid option. Please choose 1, 2, 3, or q.")
            continue

        result = analyze_email(email_text)
        print_results(result)

        again = input("Analyze another email? (y/n): ").strip().lower()
        if again != "y":
            print("\nGoodbye!\n")
            break


if __name__ == "__main__":
    main()
