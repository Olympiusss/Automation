"""
SentinelOne AI Query Agent - LLM Integration (Gemini)
This module handles the connection to Google Gemini for natural language processing.
"""

import json
import os
import time
from typing import Dict, Any, List, Optional

# Gemini imports
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from agent_tools import AGENT_TOOLS, execute_tool, format_tool_result_for_display


# Rate limiting configuration
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5  # Wait 5 seconds between retries


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


def configure_gemini(api_key: str) -> bool:
    """
    Configure the Gemini API client.
    
    Args:
        api_key: Google Gemini API key
    
    Returns:
        True if configuration successful, False otherwise
    """
    if not GEMINI_AVAILABLE:
        return False
    
    try:
        genai.configure(api_key=api_key)
        return True
    except Exception as e:
        print(f"Error configuring Gemini: {e}")
        return False


def get_gemini_model(model_name: str = "gemini-2.0-flash"):
    """
    Get a Gemini generative model instance.
    
    Args:
        model_name: Name of the model to use
    
    Returns:
        GenerativeModel instance or None if unavailable
    """
    if not GEMINI_AVAILABLE:
        return None
    
    try:
        return genai.GenerativeModel(model_name)
    except Exception as e:
        print(f"Error getting Gemini model: {e}")
        return None


def _call_gemini_with_retry(model, prompt: str, max_retries: int = MAX_RETRIES) -> tuple:
    """
    Call Gemini API with retry logic for rate limits.
    
    Args:
        model: Gemini model instance
        prompt: The prompt to send
        max_retries: Maximum number of retries
    
    Returns:
        Tuple of (success: bool, response_text: str or error_message: str)
    """
    for attempt in range(max_retries):
        try:
            response = model.generate_content(prompt)
            return True, response.text.strip()
        
        except Exception as e:
            error_str = str(e).lower()
            
            # Check if it's a rate limit error (429)
            if "429" in str(e) or "quota" in error_str or "rate" in error_str:
                if attempt < max_retries - 1:
                    wait_time = RETRY_DELAY_SECONDS * (attempt + 1)  # Exponential backoff
                    time.sleep(wait_time)
                    continue
                else:
                    return False, "⏳ Rate limit reached. The free tier has 15 requests/minute. Please wait a moment and try again."
            
            # Check for API key errors
            elif "api key" in error_str or "invalid" in error_str or "401" in str(e):
                return False, "🔑 Invalid API key. Please check your Gemini API key in Streamlit secrets."
            
            # Other errors
            else:
                return False, f"❌ Error: {str(e)}"
    
    return False, "❌ Failed after multiple retries. Please try again later."


def process_user_query(
    user_query: str,
    chat_history: List[Dict[str, str]],
    sites_data: list,
    fetch_functions: Dict[str, callable],
    api_key: str,
    current_date: str
) -> Dict[str, Any]:
    """
    Process a user query through the AI agent.
    
    Args:
        user_query: The user's natural language query
        chat_history: Previous messages in the conversation
        sites_data: List of available sites
        fetch_functions: Dictionary of fetch functions from automation_app
        api_key: Gemini API key
        current_date: Current date for context
    
    Returns:
        Dictionary with response and any data fetched
    """
    # Check if Gemini is available
    if not GEMINI_AVAILABLE:
        return {
            "success": False,
            "response": "❌ Gemini library not installed. Please run: pip install google-generativeai",
            "data": None
        }
    
    # Configure Gemini
    if not configure_gemini(api_key):
        return {
            "success": False,
            "response": "❌ Failed to configure Gemini API. Check your API key.",
            "data": None
        }
    
    # Get model
    model = get_gemini_model()
    if not model:
        return {
            "success": False,
            "response": "❌ Failed to initialize Gemini model.",
            "data": None
        }
    
    # Build the system prompt
    tools_json = json.dumps(AGENT_TOOLS, indent=2)
    system_prompt = SYSTEM_PROMPT.format(
        tools=tools_json,
        current_date=current_date
    )
    
    # Build conversation context
    conversation = [system_prompt]
    
    # Add chat history (last 10 messages for context)
    for msg in chat_history[-10:]:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        conversation.append(f"{role.upper()}: {content}")
    
    # Add current query
    conversation.append(f"USER: {user_query}")
    
    # Call Gemini with retry logic
    prompt = "\n\n".join(conversation)
    success, response_text = _call_gemini_with_retry(model, prompt)
    
    if not success:
        return {
            "success": False,
            "response": response_text,  # Contains the error message
            "data": None
        }
    
    # Check if response is a tool call (JSON)
    if response_text.startswith("{") and "tool" in response_text:
        try:
            tool_call = json.loads(response_text)
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
            # Not valid JSON, treat as conversational response
            pass
    
    # Conversational response
    return {
        "success": True,
        "response": response_text,
        "data": None,
        "tool_used": None
    }


def get_quick_suggestions() -> List[str]:
    """
    Get a list of quick query suggestions for the user.
    
    Returns:
        List of example queries
    """
    return [
        "What sites are available?",
        "Show me blocklisted hashes on Etranzact from Jan 1 to Jan 31, 2025",
        "How many threats were detected on MU last week?",
        "List critical vulnerabilities on Qore",
        "Show me agent health for Upfront",
        "Get all endpoints for Etranzact"
    ]
