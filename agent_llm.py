"""
SentinelOne AI Query Agent - LLM Integration (Multi-Provider)
This module handles the connection to LLM providers for natural language processing.
Supports: Groq (default), Gemini, OpenAI
"""

import json
import os
import time
from typing import Dict, Any, List, Optional, Tuple

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

from agent_tools import AGENT_TOOLS, execute_tool, format_tool_result_for_display


# Rate limiting configuration
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2


# System prompt for the agent
SYSTEM_PROMPT = """You are a SentinelOne security data assistant. You help users query security data from the SentinelOne platform.

You have access to the following tools to fetch data:

{tools}

INSTRUCTIONS:
1. When the user asks for security data, identify which tool to use based on their request.
2. Extract the required parameters from their query (site name, dates, etc.).
3. For dates, convert natural language to YYYY-MM-DD format:
   - "January 5th, 2025" → "2025-01-05"
   - "last week" → calculate the actual dates
   - "this month" → from the 1st to today
4. If you're unsure about the site name or dates, ask for clarification.
5. If the user doesn't specify a site, use list_available_sites first to show them options.

RESPONSE FORMAT:
When you need to call a tool, respond with ONLY a JSON object like this:
{{"tool": "tool_name", "params": {{"param1": "value1", "param2": "value2"}}}}

When you need to ask a clarifying question or respond conversationally, just respond in plain text.

IMPORTANT:
- Always confirm the site name matches an available site
- Always ensure dates are in YYYY-MM-DD format
- Be helpful and explain what data you're fetching

Current date: {current_date}
"""


def _call_groq(api_key: str, prompt: str, system_prompt: str) -> Tuple[bool, str]:
    """Call Groq API with retry logic."""
    try:
        client = Groq(api_key=api_key)
        
        for attempt in range(MAX_RETRIES):
            try:
                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",  # Fast and capable
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
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


def _call_gemini(api_key: str, prompt: str, system_prompt: str) -> Tuple[bool, str]:
    """Call Gemini API with retry logic."""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        
        full_prompt = f"{system_prompt}\n\n{prompt}"
        
        for attempt in range(MAX_RETRIES):
            try:
                response = model.generate_content(full_prompt)
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


def _call_openai(api_key: str, prompt: str, system_prompt: str) -> Tuple[bool, str]:
    """Call OpenAI API with retry logic."""
    try:
        client = OpenAI(api_key=api_key)
        
        for attempt in range(MAX_RETRIES):
            try:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
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
    general = secrets.get("general", {})
    
    # Priority: Groq > Gemini > OpenAI
    if GROQ_AVAILABLE and general.get("groq_api_key"):
        return "groq", general.get("groq_api_key")
    
    if GEMINI_AVAILABLE and general.get("gemini_api_key"):
        return "gemini", general.get("gemini_api_key")
    
    if OPENAI_AVAILABLE and general.get("openai_api_key"):
        return "openai", general.get("openai_api_key")
    
    # No provider available - return helpful error
    if not GROQ_AVAILABLE and not GEMINI_AVAILABLE and not OPENAI_AVAILABLE:
        return None, "No LLM library installed. Run: pip install groq"
    
    return None, "No API key configured. Add groq_api_key to secrets."


def process_user_query(
    user_query: str,
    chat_history: List[Dict[str, str]],
    sites_data: list,
    fetch_functions: Dict[str, callable],
    api_key: str,
    current_date: str,
    provider: str = "groq"
) -> Dict[str, Any]:
    """
    Process a user query through the AI agent.
    
    Args:
        user_query: The user's natural language query
        chat_history: Previous messages in the conversation
        sites_data: List of available sites
        fetch_functions: Dictionary of fetch functions from automation_app
        api_key: LLM API key
        current_date: Current date for context
        provider: Which LLM provider to use (groq, gemini, openai)
    
    Returns:
        Dictionary with response and any data fetched
    """
    # Build the system prompt
    tools_json = json.dumps(AGENT_TOOLS, indent=2)
    system_prompt = SYSTEM_PROMPT.format(
        tools=tools_json,
        current_date=current_date
    )
    
    # Build conversation context for the user prompt
    conversation_parts = []
    for msg in chat_history[-10:]:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        conversation_parts.append(f"{role.upper()}: {content}")
    
    conversation_parts.append(f"USER: {user_query}")
    prompt = "\n\n".join(conversation_parts)
    
    # Call the appropriate provider
    if provider == "groq":
        if not GROQ_AVAILABLE:
            return {"success": False, "response": "❌ Groq library not installed. Run: pip install groq", "data": None}
        success, response_text = _call_groq(api_key, prompt, system_prompt)
    
    elif provider == "gemini":
        if not GEMINI_AVAILABLE:
            return {"success": False, "response": "❌ Gemini library not installed.", "data": None}
        success, response_text = _call_gemini(api_key, prompt, system_prompt)
    
    elif provider == "openai":
        if not OPENAI_AVAILABLE:
            return {"success": False, "response": "❌ OpenAI library not installed.", "data": None}
        success, response_text = _call_openai(api_key, prompt, system_prompt)
    
    else:
        return {"success": False, "response": f"❌ Unknown provider: {provider}", "data": None}
    
    if not success:
        return {"success": False, "response": response_text, "data": None}
    
    # Check if response is a tool call (JSON)
    if response_text.startswith("{") and "tool" in response_text:
        try:
            # Extract JSON if there's extra text
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            json_str = response_text[json_start:json_end]
            
            tool_call = json.loads(json_str)
            tool_name = tool_call.get("tool")
            params = tool_call.get("params", {})
            
            # Execute the tool
            result = execute_tool(tool_name, params, sites_data, fetch_functions)
            
            # Format result for display
            formatted_result = format_tool_result_for_display(result, tool_name)
            
            return {
                "success": True,
                "response": formatted_result,
                "data": result,
                "tool_used": tool_name
            }
        except json.JSONDecodeError:
            pass
    
    # Conversational response
    return {
        "success": True,
        "response": response_text,
        "data": None,
        "tool_used": None
    }


def get_quick_suggestions() -> List[str]:
    """Get a list of quick query suggestions for the user."""
    return [
        "What sites are available?",
        "Show me blocklisted hashes on Etranzact from Jan 1 to Jan 31, 2025",
        "How many threats were detected on MU last week?",
        "List critical vulnerabilities on Qore",
        "Show me agent health for Upfront",
        "Get all endpoints for Etranzact"
    ]
