"""Cyber Threat Lab: safe educational simulations (PRD section 7.8).

Static question bank only. No real attacks, exploitation, credential
harvesting or malware execution - just multiple-choice awareness checks with
explanations. Answers are verified server-side on submit.
"""
from __future__ import annotations

LAB_MODULES = [
    {"key": "phishing", "label": "Phishing awareness",
     "blurb": "Spot the signs of phishing messages and links without clicking anything real."},
    {"key": "passwords", "label": "Password security",
     "blurb": "Learn what makes passwords strong and how breaches exploit reuse."},
    {"key": "social", "label": "Social engineering awareness",
     "blurb": "Recognise manipulation tactics used to trick people into helping attackers."},
    {"key": "malware", "label": "Malware and hash concepts",
     "blurb": "Understand how defenders identify malicious files safely."},
    {"key": "network", "label": "Network security concepts",
     "blurb": "Grasp IPs, domains and safe browsing habits."},
    {"key": "cve", "label": "Vulnerability concepts",
     "blurb": "Learn what CVEs and severity scores mean for keeping software updated."},
]

# Each: question, 4 options, answer index, explanation.
QUIZZES: dict[str, list[dict]] = {
    "phishing": [
        {"q": "You get a message: 'Your account will be locked in 24 hours, verify now at secure-login-bank.example'. What is the safest response?",
         "options": ["Click the link quickly before the deadline", "Type the bank's official address yourself and check there",
                     "Reply with your username to confirm", "Forward your password to the sender for verification"],
         "answer": 1, "why": "Urgency plus a link is the classic phishing pattern. Navigating yourself removes the trap."},
        {"q": "Which link is most suspicious?",
         "options": ["https://www.yourbank.com/login", "http://192.168.4.20/secure/login",
                     "https://www.yourbank.com/help", "https://yourbank.com/"],
         "answer": 1, "why": "Legitimate banks do not ask customers to log in via bare IP addresses."},
        {"q": "A link reads 'http://trusted-shop@evil.example/deals'. Where does it really go?",
         "options": ["trusted-shop", "evil.example", "A page about deals", "Nowhere, it is broken"],
         "answer": 1, "why": "Everything before @ can be credentials; the real host follows it."},
        {"q": "What does a defanged link like 'hxxps://evil[.]com' tell you?",
         "options": ["The link is safe", "Someone sanitised it so it cannot be clicked by accident",
                      "It is a new kind of address", "It leads to a government site"],
         "answer": 1, "why": "Analysts defang dangerous indicators when sharing them so nobody opens them accidentally."},
        {"q": "A sender address shows 'support@yourb4nk.com' for your bank 'yourbank.com'. What do you notice?",
         "options": ["Nothing wrong", "The digit 4 replaces the letter a - a lookalike domain",
                      "Banks always use numbers", "The address is too short"],
         "answer": 1, "why": "Single-character swaps are a core impersonation trick. Compare letter by letter."},
    ],
    "passwords": [
        {"q": "Which password is strongest?",
         "options": ["P@ssw0rd", "correct horse battery staple 9!", "qwerty12345", "Summer2024!"],
         "answer": 1, "why": "Length beats complexity. A long unique passphrase resists guessing far better."},
        {"q": "A breach-check says your password appeared 40,000 times in leaks. You should…",
         "options": ["Keep it, it still works", "Change it everywhere it is reused and enable two-factor auth",
                      "Add one exclamation mark", "Use it only for unimportant sites"],
         "answer": 1, "why": "Attackers automate lists of breached passwords. Reuse is what turns a leak into takeovers."},
        {"q": "Why do password managers help?",
         "options": ["They make passwords shorter", "They create and remember a unique password per site",
                      "They hide you from hackers completely", "They replace antivirus"],
         "answer": 1, "why": "Unique-per-site passwords contain any single breach to one account."},
        {"q": "What is two-factor authentication (2FA)?",
         "options": ["Two passwords", "A second proof (code, key or biometric) beyond the password",
                      "Logging in twice", "Sharing your account with two people"],
         "answer": 1, "why": "A second factor stays valid even if the password leaks."},
        {"q": "Which habit is safest?",
         "options": ["One strong password for everything", "Reusing with small variations per site",
                      "Unique random passwords via a manager, plus 2FA on important accounts", "Writing passwords in a notes app unprotected"],
         "answer": 2, "why": "Uniqueness plus a second factor is the practical gold standard."},
    ],
    "social": [
        {"q": "A caller claims to be IT support and asks for your login 'to fix an urgent issue'. Best move?",
         "options": ["Share it, they sound professional", "Refuse and contact IT through the official channel",
                      "Share only the password, not the username", "Ask them to call back in an hour"],
         "answer": 1, "why": "Real support never needs your password. Verify identity through a channel you trust."},
        {"q": "Which is a social-engineering red flag?",
         "options": ["A routine newsletter", "Authority + urgency + secrecy ('your boss demands it, tell no one')",
                      "A calendar invite from a colleague", "A software update notification"],
         "answer": 1, "why": "Pressure plus secrecy short-circuits verification - exactly what manipulators want."},
        {"q": "Someone you just met online asks detailed questions about your workplace systems. You…",
         "options": ["Answer to be friendly", "Share only public information and stay cautious",
                      "Send screenshots to help", "Give them a colleague's contact"],
         "answer": 1, "why": "Reconnaissance often looks like friendly curiosity. Public info only."},
        {"q": "A USB stick labelled 'Staff bonuses' is left in the parking lot. Safest action?",
         "options": ["Plug it into your work computer to check", "Hand it to security without plugging it in",
                      "Plug it into a personal laptop first", "Open it on a colleague's machine"],
         "answer": 1, "why": "Planted media is a classic intrusion vector. Never connect unknown devices."},
        {"q": "A message offers a prize and asks for a 'small verification fee'. This is…",
         "options": ["A lucky break", "An advance-fee scam", "A loyalty reward", "A tax refund"],
         "answer": 1, "why": "Real prizes never require payment to receive them."},
    ],
    "malware": [
        {"q": "What is a file hash (e.g. SHA-256) used for in forensics?",
         "options": ["Running the file safely", "Identifying the exact file without opening it",
                      "Deleting viruses", "Speeding up the computer"],
         "answer": 1, "why": "A hash fingerprints content: same bytes, same hash. Defenders share hashes, not malware."},
        {"q": "You receive 'Invoice.pdf.exe'. Why is it dangerous?",
         "options": ["PDFs are always dangerous", "The real extension is .exe - an executable hiding behind a fake name",
                      "It is too small", "Invoices are illegal"],
         "answer": 1, "why": "Double extensions trick users into running programs. Check the true final extension."},
        {"q": "A hash lookup says a file is 'known' (e.g. common software). That means…",
         "options": ["It is definitely safe", "It is catalogued - context only, not a safety verdict",
                      "It is definitely malware", "It cannot be scanned"],
         "answer": 1, "why": "Known-file databases record prevalence, not trustworthiness."},
        {"q": "What should you never do with a suspicious file?",
         "options": ["Hash it", "Look up its hash", "Run it to see what happens", "Check its extension"],
         "answer": 2, "why": "Execution gives code a chance to act. Static checks first, always."},
        {"q": "Multiple antivirus engines flag a file but two call it clean. Best reading?",
         "options": ["It must be safe", "Treat it as suspicious - engines disagree and caution wins",
                      "Uninstall the antivirus", "Ignore all engines forever"],
         "answer": 1, "why": "Engine votes are weighted signals, not proof. Disagreement means caution."},
    ],
    "network": [
        {"q": "What does 192.168.1.10 being 'private-use' mean?",
         "options": ["It is a hacker's address", "It only exists inside local networks, not the public Internet",
                      "It is faster", "It cannot be attacked"],
         "answer": 1, "why": "Private ranges are not Internet-routable; they identify local devices."},
        {"q": "Why check an IP's owner (ASN/organisation)?",
         "options": ["To hack it back", "Context: hosting ranges and bulletproof hosts carry different risk",
                      "It is required by law", "To slow attackers"],
         "answer": 1, "why": "Reputation plus context informs blocking and investigation priorities."},
        {"q": "A site uses plain HTTP for its login page. The risk is…",
         "options": ["None", "Credentials can be read or modified in transit",
                      "The site loads faster", "Passwords get stronger"],
         "answer": 1, "why": "Without TLS there is no confidentiality or integrity on the wire."},
        {"q": "What is a VPN exit IP to an investigator?",
         "options": ["Proof of crime", "One shared address for many users - weak attribution alone",
                      "Always safe", "Always malicious"],
         "answer": 1, "why": "Shared infrastructure blends users together; more evidence is needed."},
        {"q": "Someone's 'secure' link uses a URL shortener. Before trusting it you should…",
         "options": ["Click to find out", "Preview/expand it with a trusted expander or ask the sender",
                      "Ignore all shortened links forever", "Disable your browser"],
         "answer": 1, "why": "Shorteners hide destinations; verify before visiting."},
    ],
    "cve": [
        {"q": "What is a CVE identifier?",
         "options": ["A hacking tool", "A public ID for a specific software vulnerability",
                      "A type of virus", "An antivirus brand"],
         "answer": 1, "why": "CVEs give everyone - vendors, defenders, researchers - one shared name per flaw."},
        {"q": "A CVE has CVSS 9.8 Critical. Sensible priority?",
         "options": ["Ignore it", "Patch urgently, starting with exposed systems",
                      "Wait a year", "Delete the software's icon"],
         "answer": 1, "why": "Critical network-exploitable flaws are weaponised fast."},
        {"q": "CVSS 3.5 Low on an internal tool means…",
         "options": ["Nothing to do ever", "Routine maintenance, not an emergency",
                      "The tool is malware", "Unplug the network"],
         "answer": 1, "why": "Severity guides scheduling; low impact plus hard preconditions can wait its turn."},
        {"q": "Where should fix instructions come from?",
         "options": ["Random forum comments", "The vendor's advisory or your IT team",
                      "A stranger's direct message", "Guessing"],
         "answer": 1, "why": "Authoritative patches beat folklore; wrong 'fixes' can break or backdoor systems."},
        {"q": "Why update software even when nothing seems broken?",
         "options": ["Updates are decorative", "Fixes close flaws attackers actively scan for",
                      "To use more disk space", "Updates remove features you like"],
         "answer": 1, "why": "Most compromises exploit known, patched flaws on unpatched machines."},
    ],
}


def public_quiz(key: str) -> list[dict] | None:
    """Questions without answers (client plays blind)."""
    if key not in QUIZZES:
        return None
    return [{"id": i, "question": item["q"], "options": item["options"]}
            for i, item in enumerate(QUIZZES[key])]


def grade(key: str, answers: list) -> dict | None:
    """Score submitted answers. Never raises on bad input."""
    if key not in QUIZZES or not isinstance(answers, list):
        return None
    items = QUIZZES[key]
    results = []
    score = 0
    for i, item in enumerate(items):
        picked = answers[i] if i < len(answers) and isinstance(answers[i], int) else -1
        correct = picked == item["answer"]
        score += 1 if correct else 0
        results.append({"id": i, "picked": picked, "correct": item["answer"],
                        "was_correct": correct, "explanation": item["why"]})
    pct = round(100 * score / len(items))
    if pct == 100:
        band = "Excellent - threat-lab graduate material."
    elif pct >= 60:
        band = "Solid awareness with room to sharpen."
    else:
        band = "Worth replaying - review the explanations above."
    return {"module": key, "score": score, "total": len(items), "percent": pct,
            "band": band, "results": results}
