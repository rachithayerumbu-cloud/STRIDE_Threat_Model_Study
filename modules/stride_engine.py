"""
STRIDE Threat Engine
====================
Rule-based threat identification for the six STRIDE categories.
Each rule maps component types and data-flow patterns to concrete threats.
"""

from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Threat knowledge base
# Each entry describes one threat and the conditions that trigger it.
# ---------------------------------------------------------------------------
THREAT_RULES: List[Dict[str, Any]] = [
    # ── SPOOFING ─────────────────────────────────────────────────────────────
    {
        "id": "S1",
        "category": "Spoofing",
        "name": "User Identity Spoofing",
        "component_types": ["user", "web_application"],
        "description": (
            "An attacker impersonates a legitimate user by stealing or guessing "
            "credentials (e.g. brute-force, credential stuffing, phishing). "
            "The web application cannot distinguish the attacker from the real user."
        ),
        "likelihood": "High",
        "impact": "High",
        "mitigation": (
            "Enforce multi-factor authentication (MFA). Implement account lockout "
            "after repeated failed logins. Use HTTPS for all login pages."
        ),
        "security_control": "Multi-Factor Authentication, Account Lockout Policy",
    },
    {
        "id": "S2",
        "category": "Spoofing",
        "name": "API Endpoint Spoofing",
        "component_types": ["web_application", "external_api"],
        "description": (
            "An attacker creates a fake external API endpoint and tricks the web "
            "application into sending sensitive data (e.g. payment info) to it "
            "through DNS poisoning or man-in-the-middle attacks."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Pin TLS certificates for external API connections. Validate API "
            "responses against a strict schema. Use mutual TLS where possible."
        ),
        "security_control": "Certificate Pinning, Mutual TLS",
    },
    {
        "id": "S3",
        "category": "Spoofing",
        "name": "Session Token Hijacking",
        "component_types": ["user", "web_application"],
        "description": (
            "An attacker steals a valid session token (via XSS, network sniffing, "
            "or CSRF) and reuses it to impersonate an authenticated user."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Use HttpOnly and Secure cookie flags. Regenerate session IDs on login. "
            "Implement short session timeouts. Use CSRF tokens on state-changing requests."
        ),
        "security_control": "Secure Session Management, CSRF Protection",
    },
    # ── TAMPERING ────────────────────────────────────────────────────────────
    {
        "id": "T1",
        "category": "Tampering",
        "name": "SQL Injection",
        "component_types": ["web_application", "database"],
        "description": (
            "An attacker injects malicious SQL code through user-supplied input "
            "fields, modifying or deleting database records, or extracting "
            "unauthorised data."
        ),
        "likelihood": "High",
        "impact": "High",
        "mitigation": (
            "Use parameterised queries / prepared statements for all database calls. "
            "Apply input validation and whitelisting. Restrict database account privileges."
        ),
        "security_control": "Parameterised Queries, Input Validation, Least Privilege DB Accounts",
    },
    {
        "id": "T2",
        "category": "Tampering",
        "name": "Data Tampering in Transit",
        "component_types": ["user", "web_application", "external_api"],
        "description": (
            "An attacker intercepts and modifies data travelling between the "
            "client and server, or between the server and the payment API, "
            "altering order amounts or payment details."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Enforce HTTPS/TLS 1.2+ on all communication channels. "
            "Use HSTS headers. Sign critical payloads with HMAC."
        ),
        "security_control": "TLS Encryption, HSTS, HMAC Payload Signing",
    },
    {
        "id": "T3",
        "category": "Tampering",
        "name": "Parameter Tampering",
        "component_types": ["user", "web_application"],
        "description": (
            "An attacker manipulates HTTP request parameters (e.g. changing "
            "product price, discount code, or user ID) to modify application "
            "behaviour in unauthorised ways."
        ),
        "likelihood": "High",
        "impact": "Medium",
        "mitigation": (
            "Validate and sanitise all user-supplied parameters server-side. "
            "Never trust client-supplied pricing or privilege data. "
            "Use server-side state for sensitive values."
        ),
        "security_control": "Server-Side Validation, Integrity Checks",
    },
    # ── REPUDIATION ──────────────────────────────────────────────────────────
    {
        "id": "R1",
        "category": "Repudiation",
        "name": "Insufficient Audit Logging",
        "component_types": ["web_application", "database"],
        "description": (
            "Without comprehensive audit logs, a user can deny having performed "
            "an action (e.g. placing or cancelling an order, changing account "
            "details) and the system cannot provide evidence to the contrary."
        ),
        "likelihood": "Medium",
        "impact": "Medium",
        "mitigation": (
            "Log all security-relevant events with timestamps, user IDs, and "
            "source IPs. Store logs in a write-once, tamper-evident store. "
            "Implement centralised log management."
        ),
        "security_control": "Audit Logging, Tamper-Evident Log Storage",
    },
    {
        "id": "R2",
        "category": "Repudiation",
        "name": "Payment Transaction Repudiation",
        "component_types": ["web_application", "external_api"],
        "description": (
            "A user denies authorising a payment transaction. Without "
            "cryptographic proof or a detailed audit trail, it is impossible "
            "to refute the claim."
        ),
        "likelihood": "Low",
        "impact": "High",
        "mitigation": (
            "Retain digitally signed transaction receipts from the payment gateway. "
            "Record transaction IDs, amounts, and timestamps in an immutable log."
        ),
        "security_control": "Digital Receipts, Immutable Transaction Logs",
    },
    # ── INFORMATION DISCLOSURE ───────────────────────────────────────────────
    {
        "id": "I1",
        "category": "Information Disclosure",
        "name": "Sensitive Data Exposure in Database",
        "component_types": ["database"],
        "description": (
            "Unencrypted storage of passwords, payment card data, or personally "
            "identifiable information (PII) in the database means a data breach "
            "exposes sensitive user information directly."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Hash passwords using bcrypt/Argon2. Encrypt PII and payment data at "
            "rest. Apply column-level encryption for card numbers."
        ),
        "security_control": "Encryption at Rest, Secure Password Hashing",
    },
    {
        "id": "I2",
        "category": "Information Disclosure",
        "name": "Verbose Error Messages",
        "component_types": ["web_application"],
        "description": (
            "Detailed error messages (stack traces, SQL errors, file paths) "
            "returned to the client reveal internal system details that an "
            "attacker can use to craft targeted attacks."
        ),
        "likelihood": "High",
        "impact": "Medium",
        "mitigation": (
            "Return generic error messages to users. Log detailed errors server-side "
            "only. Disable debug mode in production."
        ),
        "security_control": "Generic Error Handling, Disabled Debug Mode",
    },
    {
        "id": "I3",
        "category": "Information Disclosure",
        "name": "Insecure Direct Object Reference (IDOR)",
        "component_types": ["user", "web_application", "database"],
        "description": (
            "An attacker changes an object identifier (e.g. order_id=1234 to "
            "order_id=1235) in a URL to access another user's data."
        ),
        "likelihood": "High",
        "impact": "Medium",
        "mitigation": (
            "Implement object-level authorisation checks. Use indirect references "
            "(UUIDs) rather than sequential IDs. Verify ownership before returning data."
        ),
        "security_control": "Authorisation Checks, Indirect Object References",
    },
    {
        "id": "I4",
        "category": "Information Disclosure",
        "name": "Unencrypted API Communication",
        "component_types": ["web_application", "external_api"],
        "description": (
            "If API calls to the payment gateway are made over HTTP rather than "
            "HTTPS, payment card details can be intercepted by a network attacker."
        ),
        "likelihood": "Low",
        "impact": "High",
        "mitigation": (
            "Enforce HTTPS for all external API calls. Reject any non-TLS connection. "
            "Verify server certificates."
        ),
        "security_control": "Mandatory TLS, Certificate Validation",
    },
    # ── DENIAL OF SERVICE ────────────────────────────────────────────────────
    {
        "id": "D1",
        "category": "Denial of Service",
        "name": "HTTP Flood / DDoS Attack",
        "component_types": ["user", "web_application"],
        "description": (
            "An attacker sends a massive volume of HTTP requests to overwhelm "
            "the web server, exhausting CPU, memory, or bandwidth, making the "
            "application unavailable to legitimate users."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Implement rate limiting and request throttling. Use a Web Application "
            "Firewall (WAF). Consider a CDN with DDoS protection."
        ),
        "security_control": "Rate Limiting, WAF, CDN",
    },
    {
        "id": "D2",
        "category": "Denial of Service",
        "name": "Database Connection Exhaustion",
        "component_types": ["web_application", "database"],
        "description": (
            "An attacker (or misconfigured application) opens a large number of "
            "database connections without releasing them, exhausting the connection "
            "pool and making the database unreachable."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Set and enforce connection pool size limits. Use connection timeouts. "
            "Monitor and alert on abnormal connection counts."
        ),
        "security_control": "Connection Pool Management, Database Monitoring",
    },
    {
        "id": "D3",
        "category": "Denial of Service",
        "name": "Resource Exhaustion via Large Payloads",
        "component_types": ["user", "web_application"],
        "description": (
            "An attacker uploads excessively large files or sends oversized "
            "request bodies, consuming server memory and disk space."
        ),
        "likelihood": "Medium",
        "impact": "Medium",
        "mitigation": (
            "Enforce strict upload size limits. Validate file types. "
            "Set maximum request body size at the web server level."
        ),
        "security_control": "Input Size Limits, File Type Validation",
    },
    # ── ELEVATION OF PRIVILEGE ───────────────────────────────────────────────
    {
        "id": "E1",
        "category": "Elevation of Privilege",
        "name": "Broken Access Control",
        "component_types": ["user", "web_application"],
        "description": (
            "A normal user accesses admin-only endpoints or functions by "
            "manipulating URLs, APIs, or tokens, gaining elevated privileges "
            "without authorisation."
        ),
        "likelihood": "High",
        "impact": "High",
        "mitigation": (
            "Implement role-based access control (RBAC). Deny access by default. "
            "Enforce authorisation checks server-side for every request."
        ),
        "security_control": "Role-Based Access Control, Default Deny Policy",
    },
    {
        "id": "E2",
        "category": "Elevation of Privilege",
        "name": "Privilege Escalation via SQL Injection",
        "component_types": ["web_application", "database"],
        "description": (
            "An attacker exploits a SQL injection vulnerability to update their "
            "user role in the database, granting themselves administrative access."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Use parameterised queries to prevent SQL injection. "
            "Apply least-privilege principle to database accounts. "
            "Restrict UPDATE/DELETE permissions for application accounts."
        ),
        "security_control": "Parameterised Queries, Least Privilege DB Roles",
    },
    {
        "id": "E3",
        "category": "Elevation of Privilege",
        "name": "JWT / Token Privilege Escalation",
        "component_types": ["user", "web_application"],
        "description": (
            "If JSON Web Tokens are signed with a weak secret or the 'none' "
            "algorithm is accepted, an attacker can modify their role claim "
            "to gain elevated privileges."
        ),
        "likelihood": "Medium",
        "impact": "High",
        "mitigation": (
            "Use strong signing secrets (RS256 or HS256 with a long random key). "
            "Reject tokens with the 'none' algorithm. Validate all claims server-side."
        ),
        "security_control": "Strong JWT Signing, Server-Side Token Validation",
    },
]


# Component types that must ALL be present for a rule to fire.
# These are types that represent specific infrastructure tiers (not the
# user/client layer), so an attack chain only makes sense when both
# the attacker-side and the target-side types exist in the system.
_STRICT_TYPES = {"database", "external_api"}


def analyse_system(system: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyse a system definition and return a list of applicable threats.

    Matching strategy
    -----------------
    * Rules that target only user-facing component types (user, web_application,
      mobile_app) fire when **any** of those types are present — the attack
      scenario is plausible from the internet even if not every tier is modelled.
    * Rules that include a "strict" type (database, external_api) require **all**
      listed types to be present, because those attacks represent specific
      inter-tier data flows that do not exist unless both ends are modelled.
    """
    component_type_map: Dict[str, List[str]] = {}
    for comp in system.get("components", []):
        ctype = comp.get("type", "")
        component_type_map.setdefault(ctype, []).append(comp.get("name", ctype))

    present_types = set(component_type_map.keys())
    threats: List[Dict[str, Any]] = []

    for rule in THREAT_RULES:
        rule_types = set(rule["component_types"])

        # Determine required match strategy
        has_strict_type = bool(rule_types & _STRICT_TYPES)
        if has_strict_type:
            # All component types in the rule must be present
            if not rule_types.issubset(present_types):
                continue
        else:
            # Any component type in the rule is sufficient
            if not (rule_types & present_types):
                continue

        affected_components: List[str] = []
        for ct in rule["component_types"]:
            affected_components.extend(component_type_map.get(ct, []))
        # Deduplicate while preserving order
        seen: set = set()
        unique_affected: List[str] = []
        for name in affected_components:
            if name not in seen:
                seen.add(name)
                unique_affected.append(name)

        threats.append(
            {
                "id": rule["id"],
                "category": rule["category"],
                "name": rule["name"],
                "affected_components": unique_affected,
                "description": rule["description"],
                "likelihood": rule["likelihood"],
                "impact": rule["impact"],
                "mitigation": rule["mitigation"],
                "security_control": rule["security_control"],
                # risk_level is computed by risk_calculator
            }
        )

    return threats


STRIDE_CATEGORIES = [
    {
        "letter": "S",
        "name": "Spoofing",
        "color": "cyan",
        "icon": "🎭",
        "description": "Impersonating another user or system to gain unauthorised access.",
    },
    {
        "letter": "T",
        "name": "Tampering",
        "color": "yellow",
        "icon": "✏️",
        "description": "Unauthorised modification of data in transit or at rest.",
    },
    {
        "letter": "R",
        "name": "Repudiation",
        "color": "purple",
        "icon": "🚫",
        "description": "Denying an action was performed due to insufficient audit evidence.",
    },
    {
        "letter": "I",
        "name": "Information Disclosure",
        "color": "orange",
        "icon": "🔓",
        "description": "Exposing confidential data to unauthorised parties.",
    },
    {
        "letter": "D",
        "name": "Denial of Service",
        "color": "red",
        "icon": "⚡",
        "description": "Making a system unavailable to legitimate users.",
    },
    {
        "letter": "E",
        "name": "Elevation of Privilege",
        "color": "green",
        "icon": "⬆️",
        "description": "Gaining permissions beyond what is legitimately authorised.",
    },
]
