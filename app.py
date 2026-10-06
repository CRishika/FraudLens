import streamlit as st
import csv
import io
import html

from utils.analyzer import (
    analyze_text,
    analyze_url,
    analyze_phone
)

from utils.database.db import (
    save_scan,
    get_scan_history
)

from utils.ocr import extract_text_from_image
from utils.ai import generate_ai_explanation


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="FraudLens 🔍",
    page_icon="🔍",
    layout="wide"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

.stApp {
    background-color: #87CEEB;
}

h1, h2, h3, h4, p, label, span {
    color: black !important;
}

.stTextArea textarea,
.stTextInput input {
    background-color: white !important;
    color: black !important;
    border: 2px solid black !important;
    border: 2px solid black !important;
    border-radius: 10px;
}

.stButton button {
    background-color: white !important;
    color: black !important;
    border: 2px solid black !important;
    border-radius: 10px;
    font-weight: bold;
}

.result-box {
    background-color: white;
    color: black;
    border: 2px solid black;
    border-radius: 12px;
    padding: 20px;
    margin-top: 10px;
}

.ai-box {
    background-color: white;
    color: black;
    border: 2px solid black;
    border-radius: 12px;
    padding: 20px;
    margin-top: 10px;
    font-size: 16px;
    line-height: 1.6;
}

.warning-box {
    background-color: #fff3cd;
    color: black;
    border: 2px solid #856404;
    border-radius: 12px;
    padding: 18px;
    margin-top: 10px;
}

.safe-box {
    background-color: #e8f5e9;
    color: black;
    border: 2px solid #2e7d32;
    border-radius: 12px;
    padding: 18px;
    margin-top: 10px;
}

.info-box {
    background-color: white;
    color: black;
    border: 2px solid black;
    border-radius: 12px;
    padding: 18px;
    margin-top: 10px;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# TITLE
# =========================================================

st.title("🔍 FraudLens")

st.subheader("Scam & Phishing Risk Analyzer")

st.write(
    "Analyze suspicious messages, URLs, phone numbers, emails and screenshots."
)


# =========================================================
# SELECTOR
# =========================================================

option = st.selectbox(
    "Select what you want to analyze:",
    [
        "📩 Message",
        "🌐 URL",
        "📱 Phone Number",
        "📧 Email",
        "📸 Screenshot",
        "📊 Dashboard"
    ]
)


# =========================================================
# RESULT DISPLAY
# =========================================================

def show_result(result):

    risk = result["risk"]
    score = result["score"]

    st.subheader("🛡️ Risk Assessment")

    st.markdown(
        f"""
        <div class="result-box">
            <h3>Risk Level: {risk}</h3>
            <h3>Risk Score: {score}/100</h3>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.progress(
        min(score, 100) / 100,
        text=f"Risk Score: {score}/100"
    )


# =========================================================
# WARNING SIGNS
# =========================================================

def show_warning_signs(result, text=""):

    st.subheader("🚨 Warning Signs")

    warnings = []

    categories = result.get(
        "categories",
        [result.get("category", "General")]
    )

    keywords = result.get("keywords", [])

    if keywords:
        warnings.append(
            "Suspicious keywords detected: "
            + ", ".join(keywords)
        )

    if categories:
        warnings.append(
            "Possible scam category: "
            + ", ".join(categories)
        )

    if result["score"] >= 50:
        warnings.append(
            "The overall risk score is high."
        )

    elif result["score"] >= 20:
        warnings.append(
            "The content contains some suspicious patterns."
        )

    else:
        warnings.append(
            "Only limited suspicious patterns were detected."
        )

    for warning in warnings:

        st.markdown(
            f"""
            <div class="warning-box">
            ⚠️ {html.escape(warning)}
            </div>
            """,
            unsafe_allow_html=True
        )


# =========================================================
# SAFETY RECOMMENDATIONS
# =========================================================

def show_safety_advice(result):

    st.subheader("🛡️ Safety Recommendations")

    advice = [
        "Do not share OTPs, passwords, PINs or CVV numbers.",
        "Avoid clicking unknown or suspicious links.",
        "Verify the sender through an official source.",
        "Do not make payments based only on an unexpected message.",
        "When in doubt, contact the organization using its official website or app."
    ]

    if result["risk"] == "HIGH":

        advice.insert(
            0,
            "🚨 Treat this content as high risk and avoid interacting with it."
        )

    elif result["risk"] == "MEDIUM":

        advice.insert(
            0,
            "⚠️ Be cautious and verify the information before taking action."
        )

    else:

        advice.insert(
            0,
            "ℹ️ No major suspicious pattern was detected, but always remain cautious."
        )

    st.markdown(
        '<div class="safe-box">',
        unsafe_allow_html=True
    )

    for item in advice:
        st.write("•", item)

    st.markdown(
        "</div>",
        unsafe_allow_html=True
    )


# =========================================================
# AI EXPLANATION
# =========================================================

def show_ai(text, result):

    st.subheader("🤖 AI Explanation")

    try:

        explanation = generate_ai_explanation(
            text,
            result["risk"],
            result["score"],
            result.get(
                "categories",
                [result.get("category", "General")]
            ),
            result.get("keywords", [])
        )

        if explanation and explanation.strip():

            safe_explanation = html.escape(
                explanation
            ).replace("\n", "<br>")

            st.markdown(
                f"""
                <div class="ai-box">
                {safe_explanation}
                </div>
                """,
                unsafe_allow_html=True
            )

        else:

            st.warning(
                "No AI explanation was generated."
            )

    except Exception as e:

        st.error(
            "AI explanation could not be generated. "
            "Make sure Ollama is running."
        )


# =========================================================
# DOWNLOAD REPORT
# =========================================================

def download_report(scan_type, input_data, result, ai_text=""):

    categories = result.get(
        "categories",
        [result.get("category", "General")]
    )

    keywords = result.get(
        "keywords",
        []
    )

    report = f"""
========================================
             FRAUDLENS 🔍
       SCAM ANALYSIS REPORT
========================================

Scan Type:
{scan_type}

Input:
{input_data}

----------------------------------------
RISK ASSESSMENT
----------------------------------------

Risk Level:
{result["risk"]}

Risk Score:
{result["score"]}/100

----------------------------------------
SCAM CATEGORIES
----------------------------------------

{", ".join(categories)}

----------------------------------------
DETECTED KEYWORDS
----------------------------------------

{", ".join(keywords) if keywords else "None"}

----------------------------------------
ANALYSIS
----------------------------------------

{result.get("reason", "Pattern-based analysis completed.")}

----------------------------------------
AI EXPLANATION
----------------------------------------

{ai_text if ai_text else "AI explanation generated inside the application."}

----------------------------------------
SAFETY NOTICE
----------------------------------------

FraudLens provides an automated risk assessment.
It does not guarantee that a message, URL or phone number
is definitely fraudulent.

Always verify suspicious information through official sources.

========================================
"""

    st.download_button(
        label="📥 Download Scan Report",
        data=report,
        file_name="FraudLens_Scan_Report.txt",
        mime="text/plain"
    )


# =========================================================
# COMPLETE ANALYSIS DISPLAY
# =========================================================

def complete_analysis(
    scan_type,
    input_data,
    result
):

    show_result(result)

    categories = result.get(
        "categories",
        [result.get("category", "General")]
    )

    keywords = result.get(
        "keywords",
        []
    )

    if categories:

        st.subheader("🏷️ Scam Categories")

        for category in categories:
            st.write("•", category)

    if keywords:

        st.subheader("🔑 Detected Keywords")

        for keyword in keywords:
            st.write("•", keyword)

    if result.get("reason"):

        st.subheader("🔎 Analysis")

        st.write(
            result["reason"]
        )

    show_warning_signs(
        result,
        input_data
    )

    show_safety_advice(
        result
    )

    st.divider()

    show_ai(
        input_data,
        result
    )

    st.divider()

    st.subheader("📥 Report")

    download_report(
        scan_type,
        input_data,
        result
    )


# =========================================================
# MESSAGE ANALYZER
# =========================================================

if option == "📩 Message":

    st.header("📩 Message Analyzer")

    message = st.text_area(
        "Enter the suspicious message:",
        height=180,
        placeholder="Paste suspicious SMS or WhatsApp message here..."
    )

    if st.button(
        "🔍 Analyze Message",
        key="message_button"
    ):

        if message.strip():

            result = analyze_text(
                message
            )

            save_scan(
                "Message",
                message,
                result["risk"],
                result["score"]
            )

            complete_analysis(
                "Message",
                message,
                result
            )

        else:

            st.warning(
                "Please enter a message."
            )


# =========================================================
# URL ANALYZER
# =========================================================

elif option == "🌐 URL":

    st.header("🌐 URL Analyzer")

    url = st.text_input(
        "Enter suspicious URL:",
        placeholder="https://example.com"
    )

    if st.button(
        "🔍 Analyze URL",
        key="url_button"
    ):

        if url.strip():

            result = analyze_url(
                url
            )

            save_scan(
                "URL",
                url,
                result["risk"],
                result["score"]
            )

            complete_analysis(
                "URL",
                url,
                result
            )

        else:

            st.warning(
                "Please enter a URL."
            )


# =========================================================
# PHONE ANALYZER
# =========================================================

elif option == "📱 Phone Number":

    st.header("📱 Phone Number Analyzer")

    phone = st.text_input(
        "Enter phone number:",
        placeholder="Enter phone number"
    )

    if st.button(
        "🔍 Analyze Phone Number",
        key="phone_button"
    ):

        if phone.strip():

            result = analyze_phone(
                phone
            )

            save_scan(
                "Phone Number",
                phone,
                result["risk"],
                result["score"]
            )

            complete_analysis(
                "Phone Number",
                phone,
                result
            )

        else:

            st.warning(
                "Please enter a phone number."
            )


# =========================================================
# EMAIL ANALYZER
# =========================================================

elif option == "📧 Email":

    st.header("📧 Email Analyzer")

    sender = st.text_input(
        "Sender email address:",
        placeholder="example@email.com"
    )

    subject = st.text_input(
        "Email subject:",
        placeholder="Enter email subject"
    )

    email_body = st.text_area(
        "Email content:",
        height=200,
        placeholder="Paste the email content here..."
    )

    if st.button(
        "🔍 Analyze Email",
        key="email_button"
    ):

        if email_body.strip():

            combined_email = (
                "Sender: "
                + sender
                + "\nSubject: "
                + subject
                + "\n\n"
                + email_body
            )

            result = analyze_text(
                combined_email
            )

            result["categories"].append(
                "Email Scam Analysis"
            )

            result["categories"] = list(
                dict.fromkeys(
                    result["categories"]
                )
            )

            save_scan(
                "Email",
                combined_email,
                result["risk"],
                result["score"]
            )

            complete_analysis(
                "Email",
                combined_email,
                result
            )

        else:

            st.warning(
                "Please enter the email content."
            )


# =========================================================
# SCREENSHOT ANALYZER
# =========================================================

elif option == "📸 Screenshot":

    st.header("📸 Screenshot Analyzer")

    uploaded_file = st.file_uploader(
        "Upload a screenshot:",
        type=[
            "png",
            "jpg",
            "jpeg"
        ]
    )

    if uploaded_file:

        st.image(
            uploaded_file,
            caption="Uploaded Screenshot",
            use_container_width=True
        )

        if st.button(
            "🔍 Analyze Screenshot",
            key="screenshot_button"
        ):

            extracted_text = extract_text_from_image(
                uploaded_file
            )

            st.subheader(
                "📝 Extracted Text"
            )

            st.text_area(
                "OCR Result",
                extracted_text,
                height=200
            )

            if extracted_text.strip():

                result = analyze_text(
                    extracted_text
                )

                save_scan(
                    "Screenshot",
                    extracted_text,
                    result["risk"],
                    result["score"]
                )

                complete_analysis(
                    "Screenshot",
                    extracted_text,
                    result
                )

            else:

                st.warning(
                    "No readable text was detected."
                )


# =========================================================
# DASHBOARD
# =========================================================

elif option == "📊 Dashboard":

    st.header("📊 FraudLens Dashboard")

    records = get_scan_history()

    if records:

        # ---------------------------------------------
        # STATISTICS
        # ---------------------------------------------

        total = len(records)

        high = sum(
            r["risk_level"] == "HIGH"
            for r in records
        )

        medium = sum(
            r["risk_level"] == "MEDIUM"
            for r in records
        )

        low = sum(
            r["risk_level"] == "LOW"
            for r in records
        )

        unknown = sum(
            r["risk_level"] == "UNKNOWN"
            for r in records
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Total Scans",
            total
        )

        c2.metric(
            "🔴 High Risk",
            high
        )

        c3.metric(
            "🟠 Medium Risk",
            medium
        )

        c4.metric(
            "🟢 Low Risk",
            low
        )

        # ---------------------------------------------
        # RISK CHART
        # ---------------------------------------------

        st.subheader(
            "📈 Risk Distribution"
        )

        chart_data = {
            "High Risk": high,
            "Medium Risk": medium,
            "Low Risk": low,
            "Unknown": unknown
        }

        st.bar_chart(
            chart_data
        )

        # ---------------------------------------------
        # SCAN TYPE STATISTICS
        # ---------------------------------------------

        st.subheader(
            "📊 Scan Type Statistics"
        )

        scan_types = {}

        for record in records:

            scan_type = record[
                "scan_type"
            ]

            scan_types[scan_type] = (
                scan_types.get(
                    scan_type,
                    0
                ) + 1
            )

        st.bar_chart(
            scan_types
        )

        # ---------------------------------------------
        # SEARCH HISTORY
        # ---------------------------------------------

        st.subheader(
            "🔎 Search Scan History"
        )

        search = st.text_input(
            "Search by scan type, risk level or input:"
        )

        filtered_records = records

        if search.strip():

            search_lower = search.lower()

            filtered_records = [
                record
                for record in records
                if search_lower in str(
                    record
                ).lower()
            ]

        st.write(
            f"Showing {len(filtered_records)} scan(s)"
        )

        # ---------------------------------------------
        # HISTORY
        # ---------------------------------------------

        for record in filtered_records:

            input_value = html.escape(
                str(
                    record["input_data"]
                )
            )

            st.markdown(
                f"""
                <div class="result-box">

                <b>Type:</b>
                {html.escape(str(record["scan_type"]))}

                <br><br>

                <b>Risk:</b>
                {html.escape(str(record["risk_level"]))}

                <br>

                <b>Score:</b>
                {html.escape(str(record["risk_score"]))}/100

                <br><br>

                <b>Input:</b>
                {input_value}

                <br><br>

                <b>Scanned At:</b>
                {html.escape(str(record["scanned_at"]))}

                </div>
                """,
                unsafe_allow_html=True
            )

        # ---------------------------------------------
        # EXPORT HISTORY
        # ---------------------------------------------

        st.subheader(
            "📥 Export Scan History"
        )

        output = io.StringIO()

        writer = csv.writer(
            output
        )

        writer.writerow([
            "ID",
            "Scan Type",
            "Input",
            "Risk Level",
            "Risk Score",
            "Scanned At"
        ])

        for record in records:

            writer.writerow([
                record["id"],
                record["scan_type"],
                record["input_data"],
                record["risk_level"],
                record["risk_score"],
                record["scanned_at"]
            ])

        st.download_button(
            label="📥 Download Scan History CSV",
            data=output.getvalue(),
            file_name="FraudLens_Scan_History.csv",
            mime="text/csv"
        )

    else:

        st.info(
            "No scan history available yet."
        )