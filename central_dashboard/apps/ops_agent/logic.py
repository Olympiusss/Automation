"""
Ops Agent — Backend Logic
Sentry Agentic AI chat configuration.
"""

OPENROUTER_MODELS = [
    {"id": "meta-llama/llama-3.3-70b-instruct:free",        "name": "Llama 3.3 70B"},
    {"id": "google/gemma-3-27b-it:free",                    "name": "Gemma 3 27B"},
    {"id": "deepseek/deepseek-chat-v3-0324:free",           "name": "DeepSeek V3"},
    {"id": "deepseek/deepseek-r1-0528:free",                "name": "DeepSeek R1"},
    {"id": "qwen/qwen3-32b:free",                           "name": "Qwen 3 32B"},
    {"id": "mistralai/mistral-small-3.1-24b-instruct:free", "name": "Mistral Small 3.1"},
]

SYSTEM_PROMPT = (
    "You are Sentry Agentic, an elite cybersecurity AI assistant for Sentrium Enterprise. "
    "You specialise in SentinelOne threat analysis, security operations, vulnerability assessment, "
    "incident response, and enterprise security strategy. Be precise, professional, and actionable. "
    "When analysing security data, structure your responses clearly with severity indicators, "
    "recommended actions, and prioritised next steps."
)

def get_config():
    return {"models": OPENROUTER_MODELS, "system_prompt": SYSTEM_PROMPT}
