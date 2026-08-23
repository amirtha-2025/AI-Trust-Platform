def analyze_prompt(prompt):

    prompt_lower = prompt.lower()

    risk_score = 0
    threats = []
    threat_details = []

    # --------------------------------------------------
    # THREAT INTELLIGENCE RULES
    # --------------------------------------------------

    suspicious_patterns = {
        "ignore previous instructions": {
            "score": 40,
            "category": "Prompt Injection",
            "severity": "HIGH",
            "reason": "Attempts to override the AI's previous instructions."
        },

        "ignore all instructions": {
            "score": 40,
            "category": "Prompt Injection",
            "severity": "HIGH",
            "reason": "Attempts to bypass the existing instruction hierarchy."
        },

        "reveal confidential": {
            "score": 35,
            "category": "Sensitive Data Extraction",
            "severity": "CRITICAL",
            "reason": "Attempts to access confidential or restricted information."
        },

        "show confidential data": {
            "score": 35,
            "category": "Sensitive Data Extraction",
            "severity": "CRITICAL",
            "reason": "Requests potentially restricted or confidential data."
        },

        "bypass security": {
            "score": 40,
            "category": "Security Bypass Attempt",
            "severity": "HIGH",
            "reason": "Attempts to bypass established security controls."
        },

        "jailbreak": {
            "score": 40,
            "category": "Jailbreak Attempt",
            "severity": "CRITICAL",
            "reason": "Attempts to manipulate the AI into bypassing safety restrictions."
        },

        "system prompt": {
            "score": 30,
            "category": "System Prompt Extraction",
            "severity": "MEDIUM",
            "reason": "Attempts to probe or extract hidden system instructions."
        },

        "password": {
            "score": 25,
            "category": "Credential Exposure",
            "severity": "HIGH",
            "reason": "The request contains a possible attempt to obtain sensitive credentials."
        },

        "api key": {
            "score": 30,
            "category": "Credential Exposure",
            "severity": "HIGH",
            "reason": "The request contains a possible attempt to obtain API credentials."
        }
    }

    # --------------------------------------------------
    # THREAT DETECTION
    # --------------------------------------------------

    for pattern, info in suspicious_patterns.items():

        if pattern in prompt_lower:

            risk_score += info["score"]

            threats.append(pattern)

            threat_details.append({
                "pattern": pattern,
                "category": info["category"],
                "severity": info["severity"],
                "reason": info["reason"]
            })

    risk_score = min(risk_score, 100)

    # --------------------------------------------------
    # SECURITY DECISION
    # --------------------------------------------------

    if risk_score >= 50:

        status = "BLOCKED"
        recommended_action = (
            "Block the request immediately and record "
            "the event for security investigation."
        )

    elif risk_score >= 25:

        status = "SUSPICIOUS"
        recommended_action = (
            "Allow only after human review and continue "
            "monitoring the activity."
        )

    else:

        status = "SAFE"
        recommended_action = (
            "Allow the request while continuing standard "
            "security monitoring."
        )

    # --------------------------------------------------
    # HIGHEST THREAT SEVERITY
    # --------------------------------------------------

    severity_priority = {
        "SAFE": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3
    }

    if threat_details:

        highest_severity = max(
            threat_details,
            key=lambda threat: severity_priority[
                threat["severity"]
            ]
        )["severity"]

    else:

        highest_severity = "NONE"

    # --------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------

    return {
        "status": status,
        "risk_score": risk_score,
        "threats": threats,
        "threat_details": threat_details,
        "highest_severity": highest_severity,
        "recommended_action": recommended_action
    }


# --------------------------------------------------
# TERMINAL TEST
# --------------------------------------------------

if __name__ == "__main__":

    user_prompt = input("Enter a prompt: ")

    result = analyze_prompt(user_prompt)

    print("\n--- AI FIREWALL RESULT ---")

    print("Status:", result["status"])
    print("Risk Score:", result["risk_score"])
    print(
        "Highest Severity:",
        result["highest_severity"]
    )
    print(
        "Recommended Action:",
        result["recommended_action"]
    )

    print("\nThreat Intelligence:")

    if result["threat_details"]:

        for threat in result["threat_details"]:

            print("\nPattern:", threat["pattern"])
            print("Category:", threat["category"])
            print("Severity:", threat["severity"])
            print("Reason:", threat["reason"])

    else:

        print("No threats detected.")