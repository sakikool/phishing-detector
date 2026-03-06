# ─────────────────────────────────────────────
# Phishing Email Detector
# Built by Saket
# How it works:
#   Step 1 - Define suspicious phrases to look for
#   Step 2 - Scan each line of the email for matches
#   Step 3 - Show the results with a threat score
# ─────────────────────────────────────────────


# ─────────────────────────────────────────────
# STEP 1: Define the rules
# Each rule has a name and a list of suspicious
# phrases we want to look for in the email.
# ─────────────────────────────────────────────

rules = [
    {
        "name": "Urgency & Pressure",
        "phrases": ["urgent", "act now", "immediately", "within 24 hours", "expires", "limited time"]
    },
    {
        "name": "Threats & Fear",
        "phrases": ["will be suspended", "will be deleted", "account terminated", "unauthorized access", "suspicious activity"]
    },
    {
        "name": "Suspicious Link Requests",
        "phrases": ["click here", "confirm your account", "verify your identity", "login to verify", "update your billing"]
    },
    {
        "name": "Asking for Personal Info",
        "phrases": ["credit card", "password", "social security", "bank account", "date of birth", "provide your"]
    },
    {
        "name": "Impersonating a Brand",
        "phrases": ["paypal", "apple", "microsoft", "amazon", "google", "irs", "netflix", "your bank"]
    },
    {
        "name": "Suspicious URLs",
        "phrases": ["http://", ".xyz", ".ru", "secure-login", "verify-account", "update-billing", "-support.com"]
    }
]


# ─────────────────────────────────────────────
# STEP 2: Scan the email
# Goes line by line through the email and checks
# if any suspicious phrases appear.
# Records which line triggered each rule.
# ─────────────────────────────────────────────

def scan_email(email_text):
    lines = email_text.split("\n")
    findings = []
    score = 0

    # Loop through each rule
    for rule in rules:
        matched_lines = []

        # Check every line of the email
        for i, line in enumerate(lines):
            line_lower = line.lower().strip()
            if not line_lower:
                continue

            # Check every phrase in this rule
            for phrase in rule["phrases"]:
                if phrase.lower() in line_lower:
                    matched_lines.append({
                        "line_num": i + 1,
                        "text": line.strip(),
                        "phrase": phrase
                    })
                    break  # only flag each line once per rule

        # If we found matches, save the finding
        if matched_lines:
            findings.append({
                "rule_name": rule["name"],
                "lines": matched_lines
            })
            score += 18  # each rule adds 18 points

    # Cap score at 100
    score = min(score, 100)
    return score, findings


# ─────────────────────────────────────────────
# STEP 3: Show the results
# Prints the threat score, verdict, and shows
# exactly which lines triggered each warning.
# ─────────────────────────────────────────────

def show_results(score, findings):
    print("\n" + "=" * 50)
    print("  PHISHING EMAIL DETECTOR — RESULTS")
    print("=" * 50)

    # Work out the verdict based on the score
    if score >= 55:
        verdict = "🚨 HIGH RISK — Likely Phishing"
        advice  = "Do not click any links or reply to this email."
    elif score >= 30:
        verdict = "⚠️  SUSPICIOUS — Be Careful"
        advice  = "This email has some warning signs."
    elif score >= 18:
        verdict = "🔍 LOW RISK — Minor Concerns"
        advice  = "A couple of things stood out but may be fine."
    else:
        verdict = "✅ LOOKS SAFE"
        advice  = "No major phishing patterns detected."

    print(f"\n  {verdict}")
    print(f"  {advice}")
    print(f"\n  Threat Score: {score}/100")

    # Simple visual score bar
    filled = int(score / 100 * 40)
    bar = "█" * filled + "░" * (40 - filled)
    print(f"  [{bar}]")

    print(f"\n{'─' * 50}")

    # Show findings or safe message
    if not findings:
        print("\n  ✓ No suspicious patterns found in this email.\n")
    else:
        print(f"  Red Flags Found: {len(findings)}\n")

        for f in findings:
            print(f"  ⚑  {f['rule_name']}")

            # Show exactly which line triggered this rule
            for match in f["lines"]:
                print(f"     Line {match['line_num']}: {match['text']}")
                print(f"     Triggered by: '{match['phrase']}'")
            print()

    # Safety tips
    print("─" * 50)
    print("  SAFETY TIPS")
    print("─" * 50)
    tips = [
        "Never click links in suspicious emails",
        "Real companies never ask for your password over email",
        "Check the actual sender address, not just the name",
        "When in doubt, go directly to the company's website",
    ]
    for tip in tips:
        print(f"  → {tip}")

    print("\n" + "=" * 50 + "\n")


# ─────────────────────────────────────────────
# MAIN: Run the program
# Shows a menu and lets you paste an email
# or load an example to test it out.
# ─────────────────────────────────────────────

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
I have attached the Q3 report you asked for.

Let me know if you have any questions!

Best,
Mike"""


def main():
    print("\n" + "=" * 50)
    print("     PHISHING EMAIL DETECTOR")
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
            print("When done type END on a new line and press Enter:\n")
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

        again = input("Analyze another email? (y/n): ").strip().lower()
        if again != "y":
            print("\nGoodbye!\n")
            break


if __name__ == "__main__":
    main()
