def detect_threats(email_text):

    text = email_text.lower()

    scores = {
        "phishing": 0,
        "impersonation": 0,
        "bec": 0,
        "financial_fraud": 0,
        "credential_theft": 0,
        "malware": 0
    }

    # PHISHING
    for word in [
        "verify your account",
        "account suspended",
        "click here",
        "confirm your account",
        "security alert",
        "verify immediately",
        "login"
    ]:
        if word in text:
            scores["phishing"] += 15

    # IMPERSONATION
    for word in [
        "i am the ceo",
        "i am the director",
        "i am your manager",
        "this is the ceo",
        "this is the director",
        "i am traveling",
        "keep this confidential"
    ]:
        if word in text:
            scores["impersonation"] += 20

    # BEC
    for word in [
        "wire transfer",
        "bank account",
        "change the bank details",
        "supplier",
        "invoice",
        "payment",
        "transfer",
        "accounts payable"
    ]:
        if word in text:
            scores["bec"] += 15

    # FINANCIAL FRAUD
    for word in [
        "send money",
        "transfer money",
        "payment required",
        "pay immediately",
        "bank details",
        "invoice payment",
        "refund"
    ]:
        if word in text:
            scores["financial_fraud"] += 15

    # CREDENTIAL THEFT
    for word in [
        "password",
        "username",
        "login credentials",
        "verify your password",
        "enter your password",
        "security code",
        "otp",
        "one time password"
    ]:
        if word in text:
            scores["credential_theft"] += 20

    # MALWARE / ATTACHMENT
    for word in [
        "open the attachment",
        "enable macros",
        "run this file",
        ".exe",
        ".scr",
        ".bat",
        "download the attachment"
    ]:
        if word in text:
            scores["malware"] += 20

    # Maximum score = 100
    for category in scores:
        scores[category] = min(scores[category], 100)

    return scores


# TEST
if __name__ == "__main__":

    test_email = """
    URGENT!

    I am the company director and I am traveling.

    Please transfer the invoice payment to
    the new bank account immediately.

    Keep this confidential.
    """

    results = detect_threats(test_email)

    print("\n==============================")
    print("       THREAT ANALYSIS")
    print("==============================")

    for threat, score in results.items():

        if score > 0:
            print(f"{threat.upper():20} {score}%")