import sys
import re

# OWASP Top 10 Patterns (basic POC rules)
OWASP_RULES = {
    "A01: Injection": [
        r"SELECT.*\+",
        r"os\.system",
        r"subprocess\.call",
        r"eval\(",
        r"exec\("
    ],

    "A02: Broken Authentication": [
        r"password\s*=\s*['\"]",
        r"md5\(",
        r"sha1\("
    ],

    "A03: Sensitive Data Exposure": [
        r"API_KEY\s*=",
        r"SECRET\s*=",
        r"token\s*=",
        r"PRIVATE_KEY"
    ],

    "A04: Insecure Design / Access Control": [
        r"allowAll\(",
        r"permitAll\(",
        r"@PermitAll"
    ],

    "A05: Security Misconfiguration": [
        r"debug\s*=\s*True",
        r"0\.0\.0\.0",
        r"disable_ssl"
    ],

    "A06: Vulnerable Components": [
        r"package-lock\.json",
        r"requirements\.txt"
    ],

    "A07: Identification Failures": [
        r"session\.cookie_secure\s*=\s*False",
        r"JWT_SECRET\s*="
    ],

    "A08: Software Integrity Failures": [
        r"pickle\.loads",
        r"yaml\.load\("
    ],

    "A09: Logging Failures": [
        r"except:\s*pass",
        r"logging\.disable"
    ],

    "A10: SSRF": [
        r"requests\.get\(",
        r"http\.client",
        r"urlopen\("
    ]
}


def scan_diff(diff_text):
    findings = []

    for category, patterns in OWASP_RULES.items():
        for pattern in patterns:
            if re.search(pattern, diff_text, re.IGNORECASE):
                findings.append((category, pattern))

    return findings


if __name__ == "__main__":

    diff_file = sys.argv[1]

    with open(diff_file, "r", encoding="utf-8") as f:
        diff_text = f.read()

    findings = scan_diff(diff_text)

    if findings:
        print("❌ OWASP Security Scan FAILED\n")
        print("Findings:")

        with open("result.txt", "w") as out:
            out.write("FAIL\n")
            for cat, pat in findings:
                out.write(f"{cat} matched pattern: {pat}\n")

        for cat, pat in findings:
            print(f"- {cat} → matched: {pat}")

        sys.exit(1)

    else:
        print("✅ OWASP Security Scan PASSED")

        with open("result.txt", "w") as out:
            out.write("PASS\nNo OWASP Top 10 issues found.\n")

        sys.exit(0)
