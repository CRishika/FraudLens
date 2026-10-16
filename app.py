import streamlit as st
import csv
import io
import html

from utils.analyzer import analyze_text, analyze_url, analyze_phone
from utils.database.db import save_scan, get_scan_history
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

if "latest_analysis" not in st.session_state:
    st.session_state.latest_analysis = None


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
.stTextArea textarea, .stTextInput input {
    background-color: white !important;
    color: black !important;
    border: 2px solid black !important;
    border-radius: 10px;
}
.stButton button, .stDownloadButton button {
    background-color: white !important;
    color: black !important;
    border: 2px solid black !important;
    border-radius: 10px;
    font-weight: bold;
}
.result-box, .ai-box, .warning-box, .safe-box, .info-box {
    color: black;
    border: 2px solid black;
    border-radius: 12px;
    padding: 18px;
    margin-top: 10px;
    overflow-wrap: anywhere;
}
.result-box, .ai-box, .info-box {
    background-color: white;
}
.ai-box {
    font-size: 16px;
    line-height: 1.6;
}
.warning-box {
    background-color: #fff3cd;
    border-color: #856404;
}
.safe-box {
    background-color: #e8f5e9;
    border-color: #2e7d32;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# PAGE TITLE
# =========================================================

st.title("🔍 FraudLens")
st.subheader("Scam & Phishing Risk Analyzer")
st.write(
    "Analyze suspicious messages, URLs, phone numbers, emails and screenshots."
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def store_analysis(scan_type, input_data, result):
    """Keep the latest result across Streamlit reruns."""

    st.session_state.latest_analysis = {
        "scan_type": scan_type,
        "input_data": input_data,
        "result": result,
        "ai_text": "",
        "ai_generated": False
    }

    try:
        save_scan(
            scan_type,
            input_data,
            result["risk"],
            result["score"]
        )
    except Exception as error:
        st.warning(
            f"Analysis completed, but saving to database failed: {error}"
        )


def get_categories(result):
    return result.get(
        "categories",
        [result.get("category", "General")]
    )


def show_result(result):
    risk = result.get("risk", "UNKNOWN")
    score = result.get("score", 0)

    st.subheader("🛡️ Risk Assessment")

    st.markdown(
        f"""
        <div class="result-box">
            <h3>Risk Level: {html.escape(str(risk))}</h3>
            <h3>Risk Score: {score}/100</h3>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.progress(
        max(0, min(score, 100)) / 100,
        text=f"Risk Score: {score}/100"
    )


def show_warning_signs(result):
    st.subheader("🚨 Warning Signs")

    keywords = result.get("keywords", [])
    categories = get_categories(result)

    if keywords:
        st.markdown(
            '<div class="warning-box">⚠️ Suspicious keywords: '
            + html.escape(", ".join(keywords))
            + "</div>",
            unsafe_allow_html=True
        )

    if categories:
        st.markdown(
            '<div class="warning-box">🏷️ Possible categories: '
            + html.escape(", ".join(categories))
            + "</div>",
            unsafe_allow_html=True
        )

    score = result.get("score", 0)

    if score >= 50:
        message = "The content has a high pattern-based risk score."
    elif score >= 20:
        message = "Some suspicious patterns were detected."
    else:
        message = "Few suspicious patterns were detected."

    st.markdown(
        f'<div class="warning-box">⚠️ {message}</div>',
        unsafe_allow_html=True
    )


def show_safety_advice(result):
    st.subheader("🛡️ Safety Recommendations")

    if result.get("risk") == "HIGH":
        st.warning("Treat this result cautiously. Avoid interacting with the content.")
    elif result.get("risk") == "MEDIUM":
        st.warning("Verify the information before taking action.")
    else:
        st.info("A low score does not guarantee that the content is safe.")

    advice = [
        "Never share OTPs, passwords, PINs or CVV numbers.",
        "Avoid clicking unexpected or suspicious links.",
        "Verify the sender using an official source.",
        "Do not make payments based only on an unexpected message.",
        "Contact the organization using its official website or app."
    ]

    for item in advice:
        st.write("•", item)


def create_report(scan_type, input_data, result, ai_text):
    categories = get_categories(result)
    keywords = result.get("keywords", [])

    return f"""
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

Risk Level: {result.get("risk", "UNKNOWN")}
Risk Score: {result.get("score", 0)}/100

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

{ai_text or "AI explanation is unavailable."}

----------------------------------------
SAFETY NOTICE
----------------------------------------

FraudLens provides an automated, pattern-based risk assessment.
It cannot guarantee that content is definitely fraudulent or safe.
Verify suspicious information through official sources.

========================================
"""


def show_ai_and_report(analysis):
    result = analysis["result"]

    st.subheader("🤖 AI Explanation")

    if not analysis["ai_generated"]:
        with st.spinner("Generating AI explanation using Gemma3..."):
            try:
                explanation = generate_ai_explanation(
                    analysis["input_data"],
                    result.get("risk", "UNKNOWN"),
                    result.get("score", 0),
                    get_categories(result),
                    result.get("keywords", [])
                )

                analysis["ai_text"] = (
                    str(explanation).strip()
                    if explanation
                    else "No AI explanation was generated."
                )

            except Exception as error:
                analysis["ai_text"] = (
                    f"AI explanation could not be generated. "
                    f"Error: {type(error).__name__}: {error}"
                )

            analysis["ai_generated"] = True
            st.session_state.latest_analysis = analysis

    st.markdown(
        '<div class="ai-box">'
        + html.escape(analysis["ai_text"]).replace("\n", "<br>")
        + "</div>",
        unsafe_allow_html=True
    )

    st.divider()
    st.subheader("📥 Download Scan Report")

    report = create_report(
        analysis["scan_type"],
        analysis["input_data"],
        result,
        analysis["ai_text"]
    )

    st.download_button(
        label="📥 Download Scan Report",
        data=report,
        file_name="FraudLens_Scan_Report.txt",
        mime="text/plain",
        key="download_latest_report"
    )


def show_latest_analysis():
    analysis = st.session_state.latest_analysis

    if not analysis:
        return

    st.divider()
    st.header("📋 Latest Analysis")

    st.caption(f"Analysis type: {analysis['scan_type']}")

    show_result(analysis["result"])

    categories = get_categories(analysis["result"])
    keywords = analysis["result"].get("keywords", [])

    st.subheader("🏷️ Scam Categories")
    for category in categories:
        st.write("•", category)

    if keywords:
        st.subheader("🔑 Detected Keywords")
        for keyword in keywords:
            st.write("•", keyword)

    reason = analysis["result"].get("reason")
    if reason:
        st.subheader("🔎 Analysis")
        st.write(reason)

    if analysis["scan_type"] == "Screenshot":
        st.subheader("📝 OCR Extracted Text")
        st.text_area(
            "Extracted screenshot content",
            value=analysis["input_data"],
            height=150,
            disabled=True,
            key="latest_ocr_text"
        )

    show_warning_signs(analysis["result"])
    show_safety_advice(analysis["result"])
    st.divider()
    show_ai_and_report(analysis)


# =========================================================
# ANALYSIS SELECTOR
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
# MESSAGE ANALYZER
# =========================================================

if option == "📩 Message":
    st.header("📩 Message Analyzer")

    message = st.text_area(
        "Enter the suspicious message:",
        height=180,
        placeholder="Paste suspicious SMS or WhatsApp message here..."
    )

    if st.button("🔍 Analyze Message", key="message_button"):
        if message.strip():
            result = analyze_text(message)
            store_analysis("Message", message, result)
        else:
            st.warning("Please enter a message.")


# =========================================================
# URL ANALYZER
# =========================================================

elif option == "🌐 URL":
    st.header("🌐 URL Analyzer")

    url = st.text_input(
        "Enter suspicious URL:",
        placeholder="https://example.com"
    )

    if st.button("🔍 Analyze URL", key="url_button"):
        if url.strip():
            result = analyze_url(url)
            store_analysis("URL", url, result)
        else:
            st.warning("Please enter a URL.")


# =========================================================
# PHONE ANALYZER
# =========================================================

elif option == "📱 Phone Number":
    st.header("📱 Phone Number Analyzer")

    phone = st.text_input(
        "Enter phone number:",
        placeholder="Enter phone number"
    )

    if st.button("🔍 Analyze Phone Number", key="phone_button"):
        if phone.strip():
            result = analyze_phone(phone)
            store_analysis("Phone Number", phone, result)
        else:
            st.warning("Please enter a phone number.")


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

    if st.button("🔍 Analyze Email", key="email_button"):
        if email_body.strip():
            combined_email = (
                f"Sender: {sender}\n"
                f"Subject: {subject}\n\n"
                f"{email_body}"
            )

            result = analyze_text(combined_email)
            result.setdefault("categories", []).append(
                "Email Scam Analysis"
            )
            result["categories"] = list(dict.fromkeys(result["categories"]))

            store_analysis("Email", combined_email, result)
        else:
            st.warning("Please enter the email content.")


# =========================================================
# SCREENSHOT ANALYZER
# =========================================================

elif option == "📸 Screenshot":
    st.header("📸 Screenshot Analyzer")

    uploaded_file = st.file_uploader(
        "Upload a screenshot:",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_file:
        st.image(
            uploaded_file,
            caption="Uploaded Screenshot",
            use_container_width=True
        )

        if st.button("🔍 Analyze Screenshot", key="screenshot_button"):
            try:
                extracted_text = extract_text_from_image(uploaded_file)

                if extracted_text.strip():
                    result = analyze_text(extracted_text)
                    store_analysis("Screenshot", extracted_text, result)
                else:
                    st.warning("No readable text was detected.")

            except Exception as error:
                st.error(f"Screenshot analysis failed: {error}")


# =========================================================
# DASHBOARD
# =========================================================

elif option == "📊 Dashboard":
    st.header("📊 FraudLens Dashboard")

    try:
        records = get_scan_history() or []
    except Exception as error:
        records = []
        st.error(f"Could not load scan history: {error}")

    if records:
        total = len(records)
        high = sum(r["risk_level"] == "HIGH" for r in records)
        medium = sum(r["risk_level"] == "MEDIUM" for r in records)
        low = sum(r["risk_level"] == "LOW" for r in records)
        unknown = sum(r["risk_level"] == "UNKNOWN" for r in records)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Scans", total)
        c2.metric("🔴 High Risk", high)
        c3.metric("🟠 Medium Risk", medium)
        c4.metric("🟢 Low Risk", low)

        st.subheader("📈 Risk Distribution")
        st.bar_chart({
            "High Risk": [high],
            "Medium Risk": [medium],
            "Low Risk": [low],
            "Unknown": [unknown]
        })

        st.subheader("📊 Scan Type Statistics")
        scan_types = {}
        for record in records:
            scan_type = record["scan_type"]
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1

        st.bar_chart({
            "Number of Scans": scan_types
        })

        st.subheader("🔎 Search Scan History")
        search = st.text_input(
            "Search by scan type, risk level or input:",
            key="history_search"
        )

        filtered_records = records
        if search.strip():
            query = search.lower()
            filtered_records = [
                record for record in records
                if query in str(record).lower()
            ]

        st.write(f"Showing {len(filtered_records)} scan(s)")

        for record in filtered_records:
            with st.expander(
                f"{record['scan_type']} | {record['risk_level']} | "
                f"{record['risk_score']}/100"
            ):
                st.write("**Input:**")
                st.text(record["input_data"])
                st.write("**Scanned at:**", record["scanned_at"])

        st.subheader("📥 Export Scan History")

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Scan Type", "Input",
            "Risk Level", "Risk Score", "Scanned At"
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
            mime="text/csv",
            key="download_history_csv"
        )

    else:
        st.info("No scan history available yet. Analyze some content first.")


# =========================================================
# PERSISTENT LATEST RESULT
# =========================================================

# Keep results visible across Streamlit reruns on the same analyzer.
# The dashboard has its own separate display.
if option != "📊 Dashboard":
    latest = st.session_state.latest_analysis

    expected_types = {
        "📩 Message": "Message",
        "🌐 URL": "URL",
        "📱 Phone Number": "Phone Number",
        "📧 Email": "Email",
        "📸 Screenshot": "Screenshot"
    }

    if latest and latest["scan_type"] == expected_types.get(option):
        show_latest_analysis()
