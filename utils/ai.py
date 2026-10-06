import ollama


def generate_ai_explanation(text, risk, score, categories, keywords):

    prompt = f"""
You are ScamShield, a scam and phishing risk analyzer.

Analyze this content:

{text}

Risk Level: {risk}
Risk Score: {score}/100
Categories: {", ".join(categories)}
Keywords: {", ".join(keywords) if keywords else "None"}

Give exactly 3 short bullet points:
- Why this may be suspicious
- What warning signs were detected
- What the user should do safely

Do not say it is definitely a scam.
Keep the answer simple.
"""

    response = ollama.chat(
        model="gemma3:latest",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]