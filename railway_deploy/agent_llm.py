"""
SentinelOne AI Query Agent - LLM Integration (Multi-Provider)
This module handles the connection to LLM providers for natural language processing.
Supports: Groq (default), Gemini, OpenAI, OpenRouter (free models)
"""

import json
import os
import time
import requests
from typing import Dict, Any, List, Optional, Tuple
from agent_tools import AGENT_TOOLS, execute_tool, format_tool_result_for_display

# Multi-agent orchestration
try:
    from soc_agents import AGENT_REGISTRY, ROUTER_SYSTEM_PROMPT, build_agent_prompt
    AGENTS_AVAILABLE = True
except ImportError:
    AGENTS_AVAILABLE = False

# Provider imports
GROQ_AVAILABLE = False
GEMINI_AVAILABLE = False
OPENAI_AVAILABLE = False

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    pass

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    pass

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    pass


# OpenRouter — free models via OpenAI-compatible API (uses requests, no extra lib)
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_FREE_MODELS = [
    {"id": "meta-llama/llama-3.3-70b-instruct:free",       "name": "Llama 3.3 70B (Free)",      "tier": "high"},
    {"id": "google/gemma-3-27b-it:free",                   "name": "Gemma 3 27B (Free)",        "tier": "high"},
    {"id": "deepseek/deepseek-chat-v3-0324:free",          "name": "DeepSeek V3 (Free)",        "tier": "high"},
    {"id": "deepseek/deepseek-r1-0528:free",               "name": "DeepSeek R1 (Free)",        "tier": "high"},
    {"id": "qwen/qwen3-32b:free",                          "name": "Qwen 3 32B (Free)",         "tier": "medium"},
    {"id": "mistralai/mistral-small-3.1-24b-instruct:free","name": "Mistral Small 3.1 (Free)",  "tier": "medium"},
]


# Rate limiting configuration
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2


# System prompt for the agent - AGENTIC ReAct MODE
SYSTEM_PROMPT = """You are an AGENTIC SentinelOne security analyst. You can reason through complex queries step-by-step, calling multiple tools to investigate and compile reports.

AVAILABLE TOOLS:
{tools}

KNOWN SITES (from SentinelOne platform): {known_sites}

TODAY'S DATE: {current_date}

HOW YOU WORK (ReAct Pattern):
You operate in a loop. Each turn you EITHER:
  A) Call a tool by outputting JSON: {{"tool": "tool_name", "params": {{...}}}}
  B) Give a final answer in plain text (when you have all the info you need)

After each tool call, you will receive the result as an OBSERVATION. You then decide whether to call another tool or give a final answer.

IMPORTANT: Output ONLY ONE thing per turn — either a single tool call JSON or a plain text answer. Never both.

QUERY TYPES:

1. SIMPLE DATA QUERIES → Call the right tool:
   - "What sites are available?" → {{"tool": "list_available_sites", "params": {{}}}}
   - "Show threats on Etranzact this month" → {{"tool": "get_threats", "params": {{...}}}}
   - "Show alerts on MU" → {{"tool": "get_alerts", "params": {{...}}}}

2. "HOW MANY" QUERIES → Use count_only=true:
   - {{"tool": "get_threats", "params": {{"site_name": "X", "start_date": "Y", "end_date": "Z", "count_only": true}}}}

3. SITE OVERVIEW → Use get_site_overview for holistic status:
   - "How is Etranzact doing?" → {{"tool": "get_site_overview", "params": {{"site_name": "Etranzact"}}}}

4. CROSS-SITE COMPARISON → Use compare_sites:
   - "Compare all sites" → {{"tool": "compare_sites", "params": {{"site_names": "all"}}}}
   - "Compare Etranzact and MU" → {{"tool": "compare_sites", "params": {{"site_names": "Etranzact, MU"}}}}

5. INVESTIGATION CHAINS → Call multiple tools across turns:
   Example: "Investigate critical threats on Default site"
   Turn 1: {{"tool": "get_threats", "params": {{"site_name": "Default site", "start_date": "...", "end_date": "..."}}}}
   (You receive threat data — find a critical threat ID)
   Turn 2: {{"tool": "get_threat_forensics", "params": {{"threat_id": "THREAT_ID_HERE"}}}}
   (You receive forensic data — MITRE, indicators, file paths)
   Turn 3: {{"tool": "get_endpoint_details", "params": {{"endpoint_name": "AFFECTED-HOST", "site_name": "Default site"}}}}
   (You receive endpoint info)
   Turn 4: Final plain text report summarizing all findings.

6. AUDIT TRAIL → Use get_activities:
   - "What happened on Etranzact last week?" → {{"tool": "get_activities", "params": {{"site_name": "Etranzact", "start_date": "...", "end_date": "..."}}}}

7. EXCLUSIONS → Use get_exclusions:
   - "What exclusions are on MU?" → {{"tool": "get_exclusions", "params": {{"site_name": "MU"}}}}

8. META / FOLLOW-UP QUESTIONS → Answer from chat history (NO tool):
   - "How did you know?" → Explain your reasoning
   - "Where did you get this data?" → "I queried the SentinelOne API."

9. GREETINGS → Answer directly (NO tool):
   - "Hello" → Greet and offer help

PROACTIVE ANALYSIS:
- When you find Critical threats, always flag them prominently with ⚠️
- When giving site overviews, highlight any concerning metrics
- When comparing sites, point out the site with the most risk
- If threats are found, suggest next investigation steps

RULES:
- ANY question asking for DATA must use a tool (never recite from memory).
- If dates are needed but not provided, ask the user.
- If site is not specified, ask the user OR use get_site_overview/compare_sites.
- For investigations, chain tools: get data → analyze → dig deeper → report.
- After finding threats, offer to investigate forensics with get_threat_forensics.

DATE CONVERSION:
- "last week" = 7 days ago to today
- "this month" = 1st of current month to today
- "last month" = 1st of previous month to last day of previous month
- "last quarter" = 3 months ago to today
- "this year" / "year-to-date" = January 1st of current year to today

EXAMPLES:

User: "Give me an overview of Etranzact"
{{"tool": "get_site_overview", "params": {{"site_name": "Etranzact"}}}}

User: "Compare threats across all sites"
{{"tool": "compare_sites", "params": {{"site_names": "all"}}}}

User: "Investigate threat 12345"
{{"tool": "get_threat_forensics", "params": {{"threat_id": "12345"}}}}

User: "Show critical alerts on MU this week"
{{"tool": "get_alerts", "params": {{"site_name": "MU", "start_date": "...", "end_date": "...", "severity": "Critical"}}}}

User: "What activity happened on Qore yesterday?"
{{"tool": "get_activities", "params": {{"site_name": "Qore", "start_date": "...", "end_date": "..."}}}}
"""


def _call_groq(api_key: str, prompt: str, system_prompt: str, image_data: bytes = None) -> Tuple[bool, str]:
    """Call Groq API with retry logic. (No vision support — image_data is ignored.)"""
    try:
        client = Groq(api_key=api_key)
        
        user_content = prompt
        if image_data:
            user_content = "[User attached an image, but this provider does not support vision. Responding to text only.]\n\n" + prompt
        
        for attempt in range(MAX_RETRIES):
            try:
                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content}
                    ],
                    temperature=0.1,
                    max_tokens=2048
                )
                return True, response.choices[0].message.content.strip()
            
            except Exception as e:
                error_str = str(e).lower()
                if "rate" in error_str or "429" in str(e) or "limit" in error_str:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                        continue
                    return False, "⏳ Rate limit reached. Please wait a moment and try again."
                elif "api" in error_str and "key" in error_str:
                    return False, "🔑 Invalid Groq API key. Please check your API key."
                else:
                    return False, f"❌ Error: {str(e)}"
        
        return False, "❌ Failed after retries."
    
    except Exception as e:
        return False, f"❌ Error initializing Groq: {str(e)}"


def _call_gemini(api_key: str, prompt: str, system_prompt: str, image_data: bytes = None) -> Tuple[bool, str]:
    """Call Gemini API with retry logic. Supports vision when image_data is provided."""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        
        full_prompt = f"{system_prompt}\n\n{prompt}"
        
        # Build content parts for multimodal
        content_parts = [full_prompt]
        if image_data:
            try:
                from PIL import Image as PILImage
                from io import BytesIO
                img = PILImage.open(BytesIO(image_data))
                content_parts = [full_prompt, img]
            except Exception:
                content_parts = [full_prompt + "\n\n[User attached an image but it could not be processed.]"]
        
        for attempt in range(MAX_RETRIES):
            try:
                response = model.generate_content(content_parts)
                return True, response.text.strip()
            
            except Exception as e:
                error_str = str(e).lower()
                if "429" in str(e) or "quota" in error_str or "rate" in error_str:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                        continue
                    return False, "⏳ Rate limit reached. Please wait a moment and try again."
                else:
                    return False, f"❌ Error: {str(e)}"
        
        return False, "❌ Failed after retries."
    
    except Exception as e:
        return False, f"❌ Error: {str(e)}"


def _call_openai(api_key: str, prompt: str, system_prompt: str, image_data: bytes = None) -> Tuple[bool, str]:
    """Call OpenAI API with retry logic. Supports vision when image_data is provided."""
    try:
        client = OpenAI(api_key=api_key)
        
        # Build user content (text or multimodal)
        if image_data:
            import base64
            b64_img = base64.b64encode(image_data).decode()
            user_content = [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64_img}"}}
            ]
        else:
            user_content = prompt
        
        for attempt in range(MAX_RETRIES):
            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content}
                    ],
                    temperature=0.1,
                    max_tokens=2048
                )
                return True, response.choices[0].message.content.strip()
            
            except Exception as e:
                error_str = str(e).lower()
                if "rate" in error_str or "429" in str(e):
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                        continue
                    return False, "⏳ Rate limit reached. Please wait a moment and try again."
                else:
                    return False, f"❌ Error: {str(e)}"
        
        return False, "❌ Failed after retries."
    
    except Exception as e:
        return False, f"❌ Error: {str(e)}"


def get_available_provider(secrets: dict) -> Tuple[str, str]:
    """
    Determine which LLM provider to use based on available API keys and libraries.
    
    Returns:
        Tuple of (provider_name, api_key) or (None, error_message)
    """
    import os
    general = secrets.get("general", {}) if secrets else {}
    
    # Priority: Groq > Gemini > OpenAI > OpenRouter
    groq_key = general.get("groq_api_key") or os.environ.get("GROQ_API_KEY")
    if GROQ_AVAILABLE and groq_key:
        return "groq", groq_key
        
    gemini_key = general.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if GEMINI_AVAILABLE and gemini_key:
        return "gemini", gemini_key
        
    openai_key = general.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
    if OPENAI_AVAILABLE and openai_key:
        return "openai", openai_key
    
    # OpenRouter as fallback (uses requests, always available)
    openrouter_key = general.get("openrouter_api_key") or os.environ.get("OPENROUTER_API_KEY")
    if openrouter_key:
        return "openrouter", openrouter_key
    
    # No provider available - return helpful error
    if not GROQ_AVAILABLE and not GEMINI_AVAILABLE and not OPENAI_AVAILABLE:
        return None, "No LLM library installed. Run: pip install groq, or add openrouter_api_key to secrets."
    
    return None, "No API key configured. Add groq_api_key or openrouter_api_key to secrets."


def _call_openrouter(api_key: str, prompt: str, system_prompt: str, model_id: str = None, image_data: bytes = None) -> Tuple[bool, str]:
    """Call OpenRouter API with free models. Supports vision for compatible models.
    Automatically falls back to other models if selected model is unavailable."""
    if not model_id:
        model_id = OPENROUTER_FREE_MODELS[0]["id"]
    
    # Build fallback list: selected model first, then all others
    fallback_ids = [model_id]
    for m in OPENROUTER_FREE_MODELS:
        if m["id"] != model_id:
            fallback_ids.append(m["id"])
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://sentry-agentic.streamlit.app",
        "X-Title": "Sentry Agentic",
    }
    
    # Build user content (text or multimodal)
    if image_data:
        import base64
        b64_img = base64.b64encode(image_data).decode()
        user_content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64_img}"}}
        ]
    else:
        user_content = prompt
    
    last_error = ""
    for mid in fallback_ids:
        payload = {
            "model": mid,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.1,
            "max_tokens": 2048,
        }
        
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.post(OPENROUTER_BASE_URL, headers=headers, json=payload, timeout=60)
                if resp.status_code == 200:
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    return True, content.strip()
                elif resp.status_code == 429:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                        continue
                    last_error = "⏳ Rate limit reached. Please wait a moment and try again."
                    break  # Try next model
                else:
                    error_msg = resp.json().get("error", {}).get("message", resp.text)
                    # If model is unavailable, try next one
                    if "no endpoints" in error_msg.lower() or "not found" in error_msg.lower() or resp.status_code == 404:
                        last_error = f"Model {mid} unavailable, trying next..."
                        break  # Try next model
                    return False, f"❌ OpenRouter error: {error_msg}"
            except requests.exceptions.Timeout:
                if attempt < MAX_RETRIES - 1:
                    continue
                last_error = "⏳ Request timed out."
                break  # Try next model
            except Exception as e:
                return False, f"❌ Error: {str(e)}"
    
    return False, f"❌ All models unavailable. Last error: {last_error}"


def _call_llm(provider: str, api_key: str, prompt: str, system_prompt: str, image_data: bytes = None, model_id: str = None):
    """Route to the correct LLM provider."""
    if provider == "groq":
        if not GROQ_AVAILABLE:
            return False, "❌ Groq library not installed. Run: pip install groq"
        return _call_groq(api_key, prompt, system_prompt, image_data=image_data)
    elif provider == "gemini":
        if not GEMINI_AVAILABLE:
            return False, "❌ Gemini library not installed."
        return _call_gemini(api_key, prompt, system_prompt, image_data=image_data)
    elif provider == "openai":
        if not OPENAI_AVAILABLE:
            return False, "❌ OpenAI library not installed."
        return _call_openai(api_key, prompt, system_prompt, image_data=image_data)
    elif provider == "openrouter":
        return _call_openrouter(api_key, prompt, system_prompt, model_id=model_id, image_data=image_data)
    else:
        return False, f"❌ Unknown provider: {provider}"


def _extract_tool_call(response_text: str):
    """Extract a JSON tool call from LLM response text. Returns (tool_call_dict, None) or (None, plain_text)."""
    if "{" in response_text and "tool" in response_text:
        try:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            json_str = response_text[json_start:json_end]
            tool_call = json.loads(json_str)
            if tool_call.get("tool"):
                return tool_call, None
        except json.JSONDecodeError:
            pass
    return None, response_text


MAX_REACT_STEPS = 8


def _route_query(user_query: str, provider: str, api_key: str, model_id: str = None) -> str:
    """Route a user query to the best specialist agent. Returns agent key."""
    if not AGENTS_AVAILABLE:
        return "triage"
    agents_list = "\n".join(
        f"- {key}: {cfg['name']} — {cfg['role']}"
        for key, cfg in AGENT_REGISTRY.items()
    )
    router_prompt = ROUTER_SYSTEM_PROMPT.format(agents_list=agents_list)
    success, response = _call_llm(provider, api_key, user_query, router_prompt, model_id=model_id)
    if success:
        agent_key = response.strip().lower().replace('"', '').replace("'", "").strip()
        if agent_key in AGENT_REGISTRY:
            return agent_key
    return "triage"


def process_user_query(
    user_query: str,
    chat_history: List[Dict[str, str]],
    sites_data: list,
    api_key: str,
    current_date: str,
    provider: str = "groq",
    image_data: bytes = None,
    model_id: str = None
) -> Dict[str, Any]:
    """
    Process a user query through the AI agent using a ReAct loop.
    The agent can call multiple tools in sequence to investigate complex queries.
    Now includes multi-agent routing via the 13-agent swarm orchestrator.
    """
    # Route query to the best specialist agent
    agent_key = _route_query(user_query, provider, api_key, model_id=model_id)
    agent_name = AGENT_REGISTRY.get(agent_key, {}).get("name", "Triage Agent") if AGENTS_AVAILABLE else "General Agent"

    # Build system prompt with dynamic site names from SentinelOne
    tools_json = json.dumps(AGENT_TOOLS, indent=2)
    site_names = [s.get("name", "Unknown") for s in sites_data if isinstance(s, dict)] if sites_data else []
    known_sites_str = ", ".join(site_names) if site_names else "(use list_available_sites to discover)"

    # Use agent-specific prompt if available, else fall back to generic
    if AGENTS_AVAILABLE:
        system_prompt = build_agent_prompt(agent_key, current_date, known_sites_str, tools_json)
    else:
        system_prompt = SYSTEM_PROMPT.format(
            tools=tools_json,
            current_date=current_date,
            known_sites=known_sites_str
        )

    # Build initial conversation context
    conversation_parts = []
    for msg in chat_history[-10:]:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        conversation_parts.append(f"{role.upper()}: {content}")
    conversation_parts.append(f"USER: {user_query}")

    # Scratchpad tracks tool calls and observations within this query
    scratchpad = []
    all_tool_results = []

    for step in range(MAX_REACT_STEPS):
        # Build prompt: conversation + scratchpad
        prompt = "\n\n".join(conversation_parts)
        if scratchpad:
            prompt += "\n\n--- INVESTIGATION SCRATCHPAD ---\n" + "\n".join(scratchpad)
            prompt += "\n\nBased on the observations above, decide: call another tool for more info, or give your final answer in plain text."

        # Call LLM (pass image only on first step)
        step_image = image_data if step == 0 else None
        success, response_text = _call_llm(provider, api_key, prompt, system_prompt, image_data=step_image, model_id=model_id)
        if not success:
            return {"success": False, "response": response_text, "data": None}

        # Check if response is a tool call or a final answer
        tool_call, plain_text = _extract_tool_call(response_text)

        if tool_call is None:
            # Final answer — if we used tools, prepend a summary header
            final_response = plain_text
            if all_tool_results:
                return {
                    "success": True,
                    "response": final_response,
                    "data": all_tool_results,
                    "tool_used": "investigation",
                    "steps": len(scratchpad),
                    "agent_name": agent_name
                }
            else:
                return {
                    "success": True,
                    "response": final_response,
                    "data": None,
                    "tool_used": None,
                    "agent_name": agent_name
                }

        # It's a tool call — execute it
        tool_name = tool_call.get("tool")
        params = tool_call.get("params", {})
        result = execute_tool(tool_name, params, sites_data)
        all_tool_results.append({"tool": tool_name, "params": params, "result": result})

        # If this is a simple single-step query (step 0) and the result is straightforward,
        # return it directly without re-prompting the LLM
        if step == 0 and result.get("success"):
            # Check if the original query is simple (not an investigation/complex query)
            query_lower = user_query.lower()
            is_complex = any(word in query_lower for word in [
                "investigate", "analyze", "analyse", "deep dive", "look into",
                "lateral", "correlate", "cross-reference", "check the host",
                "more details", "dig deeper", "what happened"
            ])
            if not is_complex:
                # Simple query — return result directly
                formatted = format_tool_result_for_display(result, tool_name)
                return {
                    "success": True,
                    "response": formatted,
                    "data": result,
                    "tool_used": tool_name,
                    "agent_name": agent_name
                }

        # Complex query — add observation to scratchpad and loop
        observation = json.dumps(result, indent=2, default=str)
        # Truncate large observations to avoid token overflow
        if len(observation) > 3000:
            observation = observation[:3000] + "\n... (truncated)"
        scratchpad.append(f"TOOL CALL (Step {step + 1}): {tool_name}({json.dumps(params)})")
        scratchpad.append(f"OBSERVATION: {observation}")

    # If we exhausted all steps, compile whatever we have
    if all_tool_results:
        # Format all results
        parts = [f"🔍 **Investigation completed ({len(all_tool_results)} steps):**\n"]
        for tr in all_tool_results:
            formatted = format_tool_result_for_display(tr["result"], tr["tool"])
            parts.append(formatted)
        return {
            "success": True,
            "response": "\n\n".join(parts),
            "data": all_tool_results,
            "tool_used": "investigation",
            "agent_name": agent_name
        }

    return {"success": False, "response": "❌ Could not process the query.", "data": None}


def get_quick_suggestions() -> List[str]:
    """Get a list of quick query suggestions for the user."""
    return [
        "What sites are available?",
        "Show me blocklisted hashes on Etranzact from Jan 1 to Jan 31, 2025",
        "How many threats were detected on MU last week?",
        "Investigate threats on Default site from last week",
        "Show me agent health for Upfront",
        "Get all endpoints for Etranzact"
    ]

