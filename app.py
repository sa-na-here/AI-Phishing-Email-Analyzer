import streamlit as st
import re
from urllib.parse import urlparse
import os
import joblib

# =========================================================
# ML MODEL
# =========================================================

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "phishing_model.joblib"
)

ml_model = joblib.load(MODEL_PATH)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="AI Phishing Email Analyzer",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)


# =========================================================
# PROFESSIONAL UI STYLING
# =========================================================

st.markdown(
    """
    <style>

    .main {
        padding-top: 2rem;
    }

    .app-header {
        text-align: center;
        padding: 1rem 0 1.5rem 0;
    }

    .app-title {
        font-size: 2.4rem;
        font-weight: 700;
        margin-bottom: 0.4rem;
    }

    .app-subtitle {
        font-size: 1rem;
        opacity: 0.75;
    }

    .score-card {
        padding: 1.5rem;
        border-radius: 16px;
        border: 1px solid rgba(128, 128, 128, 0.25);
        text-align: center;
        margin: 1rem 0;
    }

    .score-number {
        font-size: 3rem;
        font-weight: 800;
        margin: 0.3rem 0;
    }

    .score-label {
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        opacity: 0.7;
    }

    .sender-box {
        padding: 1rem;
        border-radius: 12px;
        border: 1px solid rgba(128, 128, 128, 0.25);
        margin: 0.7rem 0;
    }

    .ai-box {
        padding: 1.2rem;
        border-radius: 14px;
        border: 1px solid rgba(128, 128, 128, 0.25);
        margin: 0.8rem 0;
        line-height: 1.6;
    }

    .footer {
        text-align: center;
        padding: 2rem 0 1rem 0;
        font-size: 0.8rem;
        opacity: 0.55;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
    <div class="app-header">
        <div class="app-title">🛡️ AI Phishing Email Analyzer</div>
        <div class="app-subtitle">
            Analyze suspicious emails using explainable security indicators
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# =========================================================
# KNOWN BRANDS
# =========================================================

KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "google": ["google.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"]
}


# =========================================================
# BRAND IMPERSONATION ANALYSIS
# =========================================================

def analyze_brand_impersonation(domain):

    domain = domain.lower()

    detected_brand = None
    expected_domains = []
    impersonation_signals = []

    for brand, official_domains in KNOWN_BRANDS.items():

        brand_word = brand.replace(" ", "")

        normalized_domain = (
            domain
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
        )

        if brand_word in domain:

            detected_brand = brand
            expected_domains = official_domains
            break

        if brand_word in normalized_domain:

            detected_brand = brand
            expected_domains = official_domains
            break

    if detected_brand is None:

        return None, [], False

    if domain in expected_domains:

        return detected_brand, [], False

    impersonation_signals.append(
        f"The domain resembles {detected_brand.title()} "
        "but does not match its expected official domain."
    )

    if any(
        number in domain
        for number in ["0", "1", "3", "5"]
    ):

        impersonation_signals.append(
            "The domain contains characters that may be "
            "used to imitate the brand name."
        )

    return (
        detected_brand,
        impersonation_signals,
        True
    )


# =========================================================
# SENDER ANALYSIS
# =========================================================

def analyze_sender(sender_email):

    domain = sender_email.split("@")[-1].lower()

    signals = []
    suspicious_score = 0

    suspicious_words = [
        "verify",
        "security",
        "secure",
        "account",
        "login",
        "signin",
        "support",
        "update",
        "confirm",
        "alert"
    ]

    if any(
        word in domain
        for word in suspicious_words
    ):

        signals.append(
            "Security/account-related wording appears in the domain."
        )

        suspicious_score += 5

    substitution_patterns = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s"
    }

    substitutions = []

    for number, letter in substitution_patterns.items():

        if number in domain:

            substitutions.append(
                f"{number} instead of {letter}"
            )

    if substitutions:

        signals.append(
            "Character substitution may be used to imitate "
            "a familiar brand or domain."
        )

        suspicious_score += 15

    if domain.count("-") >= 2:

        signals.append(
            "The domain contains multiple hyphens."
        )

        suspicious_score += 5

    domain_parts = domain.split(".")

    if len(domain_parts) >= 3:

        signals.append(
            "The domain contains multiple subdomain levels."
        )

        suspicious_score += 5

    (
        detected_brand,
        brand_signals,
        is_impersonation
    ) = analyze_brand_impersonation(domain)

    if is_impersonation:

        suspicious_score += 25
        signals.extend(brand_signals)

    if suspicious_score >= 20:

        severity = "High"

    elif suspicious_score >= 5:

        severity = "Medium"

    else:

        severity = "Low"

    return (
        domain,
        signals,
        severity,
        detected_brand,
        is_impersonation
    )


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    signals = []
    score = 0

    # IP address
    if re.match(
        r'^\d+\.\d+\.\d+\.\d+',
        domain
    ):

        signals.append(
            "The URL uses an IP address instead of a normal domain."
        )

        score += 25

    # @ symbol
    if "@" in url:

        signals.append(
            "The URL contains an @ symbol that may obscure "
            "the actual destination."
        )

        score += 25

    # HTTP
    if parsed.scheme.lower() == "http":

        signals.append(
            "The connection uses HTTP instead of HTTPS."
        )

        score += 10

    # Long URL
    if len(url) > 120:

        signals.append(
            "The URL is unusually long."
        )

        score += 10

    # Suspicious path
    suspicious_path_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "confirm",
        "update",
        "billing"
    ]

    if any(
        word in path
        for word in suspicious_path_words
    ):

        signals.append(
            "The URL path contains a sensitive action such as "
            "login, verification, account, or password."
        )

        score += 10

    # URL shorteners
    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "shorturl.at"
    ]

    if domain in shortener_domains:

        signals.append(
            "The URL uses a link-shortening service, "
            "which hides the final destination."
        )

        score += 15

    # Deep subdomains
    domain_parts = domain.split(".")

    if len(domain_parts) >= 4:

        signals.append(
            "The URL contains an unusually deep subdomain structure."
        )

        score += 10

    # Brand impersonation
    (
        detected_brand,
        brand_signals,
        is_impersonation
    ) = analyze_brand_impersonation(domain)

    if is_impersonation:

        signals.append(
            f"The URL appears to imitate {detected_brand.title()} "
            "without using the expected official domain."
        )

        score += 25

    score = min(score, 50)

    return (
        domain,
        signals,
        score
    )


# =========================================================
# EMAIL ANALYSIS
# =========================================================

def analyze_email(email):

    email_lower = email.lower()

    risk_score = 0
    findings = []
    url_details = []

    # =====================================================
    # URGENT LANGUAGE
    # =====================================================

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "account will be closed",
        "account will be suspended",
        "final warning",
        "last warning",
        "action required",
        "failure to",
        "verify immediately"
    ]

    if any(
        word in email_lower
        for word in urgency_words
    ):

        risk_score += 20

        findings.append({
            "severity": "High",
            "category": "Urgency",
            "title": "Urgent or threatening language",
            "description": (
                "The email creates pressure by using urgent "
                "or threatening language."
            )
        })

    # =====================================================
    # SENDER
    # =====================================================

    sender_match = re.search(
        r'from:\s*(?:.*?<)?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        email,
        re.IGNORECASE
    )

    sender_email = None
    sender_domain = None

    if sender_match:

        sender_email = sender_match.group(1)

        (
            sender_domain,
            sender_signals,
            sender_severity,
            detected_brand,
            is_impersonation
        ) = analyze_sender(sender_email)

        if is_impersonation:

            risk_score += 25

            findings.append({
                "severity": "High",
                "category": "Sender",
                "title": "Possible brand impersonation",
                "description": (
                    f"The sender domain {sender_domain} appears "
                    f"to imitate {detected_brand.title()} but does "
                    "not match the expected official domain."
                )
            })

        elif sender_severity == "High":

            risk_score += 20

            findings.append({
                "severity": "High",
                "category": "Sender",
                "title": "Potentially suspicious sender",
                "description": (
                    f"The sender {sender_email} uses a domain "
                    "with several suspicious characteristics."
                )
            })

        elif sender_severity == "Medium":

            risk_score += 5

            findings.append({
                "severity": "Medium",
                "category": "Sender",
                "title": "Sender requires verification",
                "description": (
                    f"The sender is {sender_email}. "
                    "The domain contains characteristics worth "
                    "verifying before trusting the message."
                )
            })

    # =====================================================
    # CREDENTIALS
    # =====================================================

    credential_words = [
        "password",
        "passcode",
        "login",
        "log in",
        "username",
        "security code",
        "verification code",
        "otp",
        "one-time password"
    ]

    if any(
        word in email_lower
        for word in credential_words
    ):

        risk_score += 25

        findings.append({
            "severity": "High",
            "category": "Credentials",
            "title": "Possible credential request",
            "description": (
                "The message mentions passwords, login credentials, "
                "verification codes, or similar sensitive information."
            )
        })

    # =====================================================
    # FINANCIAL INFORMATION
    # =====================================================

    financial_words = [
        "credit card",
        "debit card",
        "bank account",
        "routing number",
        "payment",
        "billing information",
        "financial information",
        "card number"
    ]

    if any(
        word in email_lower
        for word in financial_words
    ):

        risk_score += 25

        findings.append({
            "severity": "High",
            "category": "Financial",
            "title": "Financial information mentioned",
            "description": (
                "The email requests or discusses sensitive "
                "financial information."
            )
        })

    # =====================================================
    # URLS
    # =====================================================

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        email
    )

    if urls:

        risk_score += 5

        findings.append({
            "severity": "Medium",
            "category": "Links",
            "title": "Link detected",
            "description": (
                f"The email contains {len(urls)} link(s). "
                "Links should be checked carefully before clicking."
            )
        })

        total_url_risk = 0

        for url in urls:

            (
                domain,
                signals,
                url_score
            ) = analyze_url(url)

            total_url_risk += url_score

            url_details.append({
                "url": url,
                "domain": domain,
                "signals": signals,
                "score": url_score
            })

        total_url_risk = min(
            total_url_risk,
            30
        )

        risk_score += total_url_risk

        if total_url_risk >= 20:

            findings.append({
                "severity": "High",
                "category": "Links",
                "title": "Suspicious URL characteristics",
                "description": (
                    "One or more links contain characteristics "
                    "commonly associated with suspicious URLs."
                )
            })

        elif total_url_risk >= 10:

            findings.append({
                "severity": "Medium",
                "category": "Links",
                "title": "URL requires caution",
                "description": (
                    "One or more links contain characteristics "
                    "that should be verified before clicking."
                )
            })

    # =====================================================
    # CLICK / VERIFY
    # =====================================================

    click_phrases = [
        "click here",
        "click the link",
        "click below",
        "verify your account",
        "confirm your account",
        "update your account",
        "sign in here"
    ]

    if any(
        phrase in email_lower
        for phrase in click_phrases
    ):

        risk_score += 10

        findings.append({
            "severity": "Medium",
            "category": "Action",
            "title": "Request to click or verify",
            "description": (
                "The email encourages the recipient to click a link "
                "or verify an account."
            )
        })

    # =====================================================
    # ATTACHMENTS
    # =====================================================

    attachment_words = [
        "attachment",
        "attached file",
        "open the attached",
        "download the attachment"
    ]

    if any(
        word in email_lower
        for word in attachment_words
    ):

        risk_score += 10

        findings.append({
            "severity": "Medium",
            "category": "Attachment",
            "title": "Attachment mentioned",
            "description": (
                "The message references an attachment. "
                "Unexpected attachments should be treated carefully."
            )
        })

    # =====================================================
    # FINAL SCORE AND CLASSIFICATION
    # =====================================================

    risk_score = min(
        risk_score,
        100
    )

    if risk_score >= 60:

        risk_level = "HIGH RISK"
        risk_icon = "🔴"
        risk_summary = "Likely phishing"

    elif risk_score >= 30:

        risk_level = "MEDIUM RISK"
        risk_icon = "🟠"
        risk_summary = "Suspicious — verify before acting"

    elif risk_score > 0:

        risk_level = "LOW RISK"
        risk_icon = "🟡"
        risk_summary = "Low risk — some caution advised"

    else:

        risk_level = "LOW RISK"
        risk_icon = "🟢"
        risk_summary = "No major phishing indicators detected"

    return (
        risk_score,
        risk_level,
        risk_icon,
        risk_summary,
        findings,
        urls,
        url_details,
        sender_email,
        sender_domain
    )


# =========================================================
# EMAIL INPUT
# =========================================================

st.subheader("📨 Email Input")

st.write(
    "Paste the complete email below, including the sender and message body."
)

email_text = st.text_area(
    "Email content",
    height=300,
    placeholder=(
        "From: security@example.com\n"
        "Subject: Urgent Account Verification\n\n"
        "Your account will be suspended today.\n"
        "Click here to verify your password."
    ),
    label_visibility="collapsed"
)


# =========================================================
# ANALYZE BUTTON
# =========================================================

analyze_button = st.button(
    "🔍 Analyze Email",
    use_container_width=True
)


# =========================================================
# RESULTS
# =========================================================

if analyze_button:

    if not email_text.strip():

        st.warning(
            "Please paste an email before analyzing."
        )

    else:

        (
            score,
            level,
            icon,
            summary,
            findings,
            urls,
            url_details,
            sender_email,
            sender_domain
        ) = analyze_email(email_text)

        # =================================================
        # MACHINE LEARNING PREDICTION
        # =================================================

        ml_prediction = ml_model.predict([email_text])[0]
        ml_probabilities = ml_model.predict_proba([email_text])[0]

        if ml_prediction == 1:
           ml_probability = ml_probabilities[1]
           ml_result = "Phishing"
        else:
           ml_probability = ml_probabilities[0]
           ml_result = "Legitimate"

        st.divider()

        # =================================================
        # RISK SCORE
        # =================================================

        st.subheader("📊 Analysis Result")

        st.markdown(
            f"""
            <div class="score-card">
                <div class="score-label">Risk Score</div>
                <div class="score-number">{score}/100</div>
                <div><strong>{icon} {level}</strong></div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.progress(score / 100)

        st.markdown(
            f"### {summary}"
        )

        # =================================================
        # INDICATOR COUNT
        # =================================================

        indicator_count = len(findings)

        if indicator_count > 0:

            st.caption(
                f"🔎 {indicator_count} security indicator(s) detected"
            )

        # =================================================
        # TOP REASONS
        # =================================================

        st.subheader("🎯 Top Reasons")

        high_findings = [
            finding
            for finding in findings
            if finding["severity"] == "High"
        ]

        medium_findings = [
            finding
            for finding in findings
            if finding["severity"] == "Medium"
        ]

        top_findings = (
            high_findings + medium_findings
        )[:5]

        if top_findings:

            for finding in top_findings:

                if finding["severity"] == "High":

                    st.markdown(
                        f"🔴 **{finding['title']}**"
                    )

                else:

                    st.markdown(
                        f"🟠 **{finding['title']}**"
                    )

        else:

            st.success(
                "No significant phishing indicators were detected."
            )

        # =================================================
        # SENDER ANALYSIS
        # =================================================

        if sender_email:

            st.subheader("👤 Sender Analysis")

            st.markdown(
                f"""
                <div class="sender-box">
                    <strong>Sender:</strong> {sender_email}<br>
                    <strong>Domain:</strong> {sender_domain}
                </div>
                """,
                unsafe_allow_html=True
            )

            sender_related = [
                finding
                for finding in findings
                if finding["category"] == "Sender"
            ]

            if sender_related:

                for finding in sender_related:

                    if finding["severity"] == "High":

                        st.error(
                            f"🔴 **{finding['title']}**\n\n"
                            f"{finding['description']}"
                        )

                    else:

                        st.info(
                            f"ℹ️ **{finding['title']}**\n\n"
                            f"{finding['description']}"
                        )

            else:

                st.success(
                    "No obvious suspicious sender characteristics detected."
                )

        # =================================================
        # DETAILED ANALYSIS
        # =================================================

        st.subheader("🔎 Detailed Analysis")

        if findings:

            for finding in findings:

                if finding["severity"] == "High":

                    st.error(
                        f"🔴 **{finding['title']}**\n\n"
                        f"{finding['description']}"
                    )

                elif finding["severity"] == "Medium":

                    st.warning(
                        f"🟠 **{finding['title']}**\n\n"
                        f"{finding['description']}"
                    )

        # =================================================
        # URL ANALYSIS
        # =================================================

        if url_details:

            st.subheader("🔗 URL Analysis")

            for detail in url_details:

                with st.expander(
                    f"🌐 {detail['domain']}"
                ):

                    st.code(
                        detail["url"]
                    )

                    if detail["signals"]:

                        for signal in detail["signals"]:

                            st.warning(
                                f"⚠️ {signal}"
                            )

                    else:

                        st.success(
                            "No obvious suspicious URL characteristics detected."
                        )

                    st.write(
                        f"URL risk contribution: "
                        f"**{detail['score']}/50**"
                    )

        # =================================================
        # AI SECURITY ASSESSMENT
        # =================================================

        st.subheader("🤖 AI Security Assessment")

        # ML MODEL RESULT
        ml_label = "Phishing" if ml_prediction == 1 else "Legitimate"
        ml_confidence = ml_probability * 100

        if ml_prediction == 1:
            st.error(
                f"🤖 **ML Classification: {ml_label}**  \n"
                f"**Model Confidence: {ml_confidence:.1f}%**"
            )
        else:
            st.success(
                f"🤖 **ML Classification: {ml_label}**  \n"
                f"**Model Confidence: {ml_confidence:.1f}%**"
            )

        st.caption(
             "The ML classification is an independent machine-learning "
             "assessment. The Risk Score above is calculated separately "
             "from the analyzer's explainable security indicators."
             )

        assessment_parts = []
        if score >= 60:

            assessment_parts.append(
                "This email shows multiple characteristics commonly "
                "associated with phishing."
            )

        elif score >= 30:

            assessment_parts.append(
                "This email contains some characteristics that "
                "may require additional verification."
            )

        elif score > 0:

            assessment_parts.append(
                "This email contains some potentially suspicious "
                "characteristics, but the available indicators do "
                "not provide strong evidence of phishing."
            )

        else:

            assessment_parts.append(
                "This email does not show major phishing indicators "
                "based on the rules currently used by the analyzer."
            )

        brand_finding = next(
            (
                finding
                for finding in findings
                if finding["title"] == "Possible brand impersonation"
            ),
            None
        )

        if brand_finding:

            assessment_parts.append(
                brand_finding["description"]
            )

        urgency_finding = next(
            (
                finding
                for finding in findings
                if finding["category"] == "Urgency"
            ),
            None
        )

        if urgency_finding:

            assessment_parts.append(
                "The message uses urgent or threatening language "
                "to pressure the recipient into acting quickly."
            )

        credential_finding = next(
            (
                finding
                for finding in findings
                if finding["category"] == "Credentials"
            ),
            None
        )

        if credential_finding:

            assessment_parts.append(
                "It mentions credentials or authentication information, "
                "which could be used to steal account access."
            )

        link_finding = next(
            (
                finding
                for finding in findings
                if finding["category"] == "Links"
            ),
            None
        )

        if link_finding:

            assessment_parts.append(
                "The message contains a link that should be "
                "verified before opening."
            )

        action_finding = next(
            (
                finding
                for finding in findings
                if finding["category"] == "Action"
            ),
            None
        )

        if action_finding:

            assessment_parts.append(
                "The recipient is encouraged to click, verify, "
                "or update an account."
            )

        financial_finding = next(
            (
                finding
                for finding in findings
                if finding["category"] == "Financial"
            ),
            None
        )

        if financial_finding:

            assessment_parts.append(
                "The message involves sensitive financial information, "
                "which is a common phishing target."
            )

        attachment_finding = next(
            (
                finding
                for finding in findings
                if finding["category"] == "Attachment"
            ),
            None
        )

        if attachment_finding:

            assessment_parts.append(
                "The message references an attachment, which should "
                "be handled carefully if it was not expected."
            )

        st.markdown(
            f"""
            <div class="ai-box">
                {" ".join(assessment_parts)}
            </div>
            """,
            unsafe_allow_html=True
        )

        # =================================================
        # RECOMMENDED ACTION
        # =================================================

        st.subheader("💡 Recommended Action")

        if score >= 60:

            st.error(
                "Do not click links, open unexpected attachments, "
                "or provide sensitive information. Verify the message "
                "through an official website or trusted contact."
            )

        elif score >= 30:

            st.warning(
                "Proceed with caution. Verify the sender and links "
                "through an independent trusted source before taking action."
            )

        elif score > 0:

            st.info(
                "Some caution is advised. Verify the sender and any "
                "links independently before taking action."
            )

        else:

            st.info(
                "The email does not show major phishing indicators, "
                "but always verify unexpected requests independently."
            )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <div class="footer">
        AI Phishing Email Analyzer • Explainable cybersecurity analysis
    </div>
    """,
    unsafe_allow_html=True
)
