
import ollama


def generate_ai_explanation(text, risk, score, categories, keywords):
    prompt = f"""
You are FraudLens, a scam and phishing risk analysis assistant.

Analyze this content:
{text}

Risk Level: {risk}
Risk Score: {score}/100
Categories: {", ".join(categories)}
Keywords: {", ".join(keywords) if keywords else "None"}

Give exactly 3 short bullet points explaining:
- Why the content may be suspicious
- Which warning signs were detected
- What the user should do safely

Do not claim the content is definitely a scam.
Keep the explanation simple.
"""

    try:
        response = ollama.chat(
            model="gemma3:latest",
            messages=[{"role": "user", "content": prompt}],
        )

        explanation = response["message"]["content"].strip()

        if explanation:
            return explanation

        return "No AI explanation was generated."

    except Exception as error:
        return (
            "AI explanation could not be generated.\n\n"
            f"Error: {type(error).__name__}: {error}"
        )
