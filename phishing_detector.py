# Phishing Email Detector
# Built by Saket
#
# How it works:
#   1. I made a list of phrases that show up a lot in phishing emails
#   2. It reads through the email line by line and checks for those phrases
#   3. If it finds something suspicious it tells you which line and why


# These are the phrases I'm looking for, grouped by what trick they're using
rules = [
    {
        "name": "Urgency & Pressure",
        "phrases": ["urgent", "act now", "immediately", "within 24 hours", "expires", "limited time"]
    },
    {
        "name": "Threats",
        "phrases": ["will be suspended", "will be deleted", "account terminated", "unauthorized access", "suspicious activity"]
    },
    {
        "name": "Sketchy Link Requests",
        "phrases": ["click here", "confirm your account", "verify your identity", "login to verify", "update your billing"]
    },
    {
        "name": "Asking for Personal Info",
        "phrases": ["credit card", "password", "social security", "bank account", "date of birth", "provide your"]
    },
    {
        "name": "Pretending to be a Brand",
        "phrases": ["paypal", "apple", "microsoft", "amazon", "google", "irs", "netflix", "your bank"]
    },
    {
        "name": "Suspicious Links",
        "phrases": ["http://", ".xyz", ".ru", "secure-login", "verify-account", "update-billing"]
    }
]


def scan_email(email_text):
    # Split the email into individual lines so I can check each one
    lines = email_text.split("\n")
    findings = []
    score = 0

    for rule in rules:
        hits = []

        for i, line in enumerate(lines):
            line_lower = line.lower().strip()
            if not line_lower:
                continue

            # Check if any of the phrases show up in this line
            for phrase in rule["phrases"]:
                if phrase in line_lower:
                    hits.append({
                        "num": i + 1,
                        "text": line.strip(),
                        "phrase": phrase
                    })
                    break

        if hits:
            findings.append({"name": rule["name"], "hits": hits})
            score += 18

    score = min(score, 100)
    return score, findings


def show_results(score, findings):
    print("\n" + "=" * 50)
    print("  Phishing Email Detector — Results")
    print("=" * 50)

    if score >= 55:
        verdict = "🚨 High Risk — This is probably a phishing email."
        advice  = "Don't click any links or reply to this."
    elif score >= 30:
        verdict = "⚠️  Looks Suspicious — Something feels off."
        advice  = "Be careful with this one."
    elif score >= 18:
        verdict = "🔍 Minor Concerns — A couple things stood out."
        advice  = "It might be fine but worth double checking."
    else:
        verdict = "✅ Looks Safe — Nothing suspicious found."
        advice  = "Seems okay!"

    print(f"\n  {verdict}")
    print(f"  {advice}")
    print(f"\n  Threat Score: {score}/100")

    filled = int(score / 100 * 40)
    bar = "█" * filled + "░" * (40 - filled)
    print(f"  [{bar}]")

    print(f"\n{'─' * 50}")

    if not findings:
        print("\n  No red flags found in this email.\n")
    else:
        print(f"  Red Flags Found: {len(findings)}\n")

        for f in findings:
            print(f"  ⚑  {f['name']}")
            for h in f["hits"]:
                print(f"     Line {h['num']}: {h['text']}")
                print(f"     Matched: '{h['phrase']}'")
            print()

    print("─" * 50)
    print("  A Few Things to Keep in Mind")
    print("─" * 50)
    print("  → Never click links in suspicious emails.")
    print("  → Real companies won't ask for your password over email.")
    print("  → Check the actual sender address, not just the display name.")
    print("  → If something feels wrong, it probably is.")
    print("\n" + "=" * 50 + "\n")


# Example emails to test with
example_phishing = """Subject: Urgent - Your Apple ID Has Been Locked

Dear Valued Customer,

We detected unauthorized access on your Apple ID account.
Your account will be suspended within 24 hours unless you act now.

Click here to verify your identity and update your billing information:
http://apple-secure-login.verify-account.xyz/login

Please provide your full name, password, and credit card number
to restore access immediately.

Apple Support Team"""

example_safe = """Hi Sarah,

Just following up on our meeting from Tuesday.
I've attached the Q3 report you asked for.

Let me know if you have any questions!

Best,
Mike"""


def main():
    print("\n" + "=" * 50)
    print("     Phishing Email Detector")
    print("     Built by Saket")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  1 - Load phishing example")
        print("  2 - Load safe email example")
        print("  3 - Paste your own email")
        print("  q - Quit")

        choice = input("\nChoose an option (1/2/3/q): ").strip().lower()

        if choice == "q":
            print("\nGoodbye!\n")
            break

        elif choice == "1":
            email_text = example_phishing
            print("\n[Loaded phishing example]")

        elif choice == "2":
            email_text = example_safe
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

        score, findings = scan_email(email_text)
        show_results(score, findings)

        again = input("Scan another email? (y/n): ").strip().lower()
        if again != "y":
            print("\nGoodbye!\n")
            break


if __name__ == "__main__":
    main()
