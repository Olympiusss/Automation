"""
SentinelOne AI Query Agent - Tool Definitions and Execution
This module defines the tools available to the AI agent and executes them.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional

# Tool definitions for the LLM
AGENT_TOOLS = [
    {
        "name": "get_blocklisted_hashes",
        "description": "Fetch blocklisted hash restrictions for a specific site within a date range. Returns hash values, OS types, descriptions, scopes, and creation dates.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Name of the site (e.g., 'Etranzact', 'MU', 'Qore', 'Upfront')"
                },
                "start_date": {
                    "type": "string",
                    "description": "Start date in YYYY-MM-DD format (e.g., '2025-01-05')"
                },
                "end_date": {
                    "type": "string",
                    "description": "End date in YYYY-MM-DD format (e.g., '2025-05-19')"
                }
            },
            "required": ["site_name", "start_date", "end_date"]
        }
    },
    {
        "name": "get_threats",
        "description": "Fetch threat data for a specific site within a date range. Returns threat classifications, affected endpoints, mitigation status, and analyst verdicts.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Name of the site"
                },
                "start_date": {
                    "type": "string",
                    "description": "Start date in YYYY-MM-DD format"
                },
                "end_date": {
                    "type": "string",
                    "description": "End date in YYYY-MM-DD format"
                }
            },
            "required": ["site_name", "start_date", "end_date"]
        }
    },
    {
        "name": "get_vulnerabilities",
        "description": "Fetch vulnerability data for a specific site. Returns application names, affected endpoints, severity levels, and NVD scores.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Name of the site"
                },
                "severity": {
                    "type": "string",
                    "description": "Optional severity filter: 'Critical', 'High', 'Medium', 'Low'",
                    "enum": ["Critical", "High", "Medium", "Low"]
                }
            },
            "required": ["site_name"]
        }
    },
    {
        "name": "get_endpoints",
        "description": "Fetch endpoint/agent data for a specific site. Returns computer names, OS distribution, agent versions, and protection status.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Name of the site"
                }
            },
            "required": ["site_name"]
        }
    },
    {
        "name": "get_agent_health",
        "description": "Fetch agent health metrics for a specific site. Returns version distribution, agents needing attention, and protection issues.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Name of the site"
                }
            },
            "required": ["site_name"]
        }
    },
    {
        "name": "list_available_sites",
        "description": "List all available sites that can be queried. Use this when the user asks what sites are available or doesn't specify a site.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]


def get_site_id_by_name(site_name: str, sites_data: list) -> Optional[str]:
    """
    Find site ID by matching site name (case-insensitive partial match).
    
    Args:
        site_name: Name of the site to find
        sites_data: List of site dictionaries from fetch_all_sites()
    
    Returns:
        Site ID if found, None otherwise
    """
    site_name_lower = site_name.lower().strip()
    
    for site in sites_data:
        if isinstance(site, dict):
            name = site.get("name", "").lower()
            site_id = site.get("id")
            
            # Exact match
            if name == site_name_lower:
                return site_id
            
            # Partial match
            if site_name_lower in name or name in site_name_lower:
                return site_id
    
    return None


def parse_date_range(start_date: str, end_date: str) -> Tuple[str, str]:
    """
    Parse date strings to ISO format for API calls.
    
    Args:
        start_date: Date in YYYY-MM-DD format
        end_date: Date in YYYY-MM-DD format
    
    Returns:
        Tuple of (start_iso, end_iso) strings
    """
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        start_iso = start_dt.strftime("%Y-%m-%dT00:00:00Z")
    except:
        start_iso = None
    
    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        # Set to end of day
        end_dt = end_dt.replace(hour=23, minute=59, second=59)
        end_iso = end_dt.strftime("%Y-%m-%dT23:59:59Z")
    except:
        end_iso = None
    
    return start_iso, end_iso


def execute_tool(
    tool_name: str, 
    params: Dict[str, Any],
    sites_data: list,
    fetch_functions: Dict[str, callable]
) -> Dict[str, Any]:
    """
    Execute the requested tool and return results.
    
    Args:
        tool_name: Name of the tool to execute
        params: Parameters for the tool
        sites_data: List of available sites
        fetch_functions: Dictionary mapping function names to actual functions
    
    Returns:
        Dictionary with results or error message
    """
    try:
        # Handle list_available_sites
        if tool_name == "list_available_sites":
            site_names = [s.get("name", "Unknown") for s in sites_data if isinstance(s, dict)]
            return {
                "success": True,
                "data": site_names,
                "message": f"Found {len(site_names)} available sites."
            }
        
        # Get site ID for site-specific queries
        site_name = params.get("site_name", "")
        site_id = get_site_id_by_name(site_name, sites_data)
        
        if not site_id:
            return {
                "success": False,
                "error": f"Site '{site_name}' not found. Use list_available_sites to see available sites."
            }
        
        # Execute based on tool name
        if tool_name == "get_blocklisted_hashes":
            start_iso, end_iso = parse_date_range(params["start_date"], params["end_date"])
            fetch_fn = fetch_functions.get("fetch_blocklisted_hashes_for_site")
            if fetch_fn:
                df_hashes, df_summary = fetch_fn(site_id, start_iso, end_iso)
                return {
                    "success": True,
                    "total_count": len(df_hashes),
                    "data": df_hashes.head(50).to_dict(orient="records"),  # Limit to 50 for display
                    "summary": df_summary.to_dict(orient="records"),
                    "message": f"Found {len(df_hashes)} blocklisted hashes for {site_name}."
                }
        
        elif tool_name == "get_threats":
            start_iso, end_iso = parse_date_range(params["start_date"], params["end_date"])
            fetch_fn = fetch_functions.get("fetch_threats_for_site")
            if fetch_fn:
                df_threats, _ = fetch_fn(site_id, start_iso, end_iso)
                return {
                    "success": True,
                    "total_count": len(df_threats),
                    "data": df_threats.head(50).to_dict(orient="records"),
                    "message": f"Found {len(df_threats)} threats for {site_name}."
                }
        
        elif tool_name == "get_vulnerabilities":
            fetch_fn = fetch_functions.get("fetch_vulnerabilities_for_site")
            if fetch_fn:
                df_vulns, df_summary = fetch_fn(site_id)
                # Filter by severity if specified
                severity = params.get("severity")
                if severity and not df_vulns.empty:
                    df_vulns = df_vulns[df_vulns["Severity"].str.lower() == severity.lower()]
                return {
                    "success": True,
                    "total_count": len(df_vulns),
                    "data": df_vulns.head(50).to_dict(orient="records"),
                    "summary": df_summary.to_dict(orient="records") if not df_summary.empty else [],
                    "message": f"Found {len(df_vulns)} vulnerabilities for {site_name}."
                }
        
        elif tool_name == "get_endpoints":
            fetch_fn = fetch_functions.get("fetch_endpoints_for_site")
            if fetch_fn:
                df_endpoints, df_os = fetch_fn(site_id)
                return {
                    "success": True,
                    "total_count": len(df_endpoints),
                    "data": df_endpoints.head(50).to_dict(orient="records"),
                    "os_distribution": df_os.to_dict(orient="records") if not df_os.empty else [],
                    "message": f"Found {len(df_endpoints)} endpoints for {site_name}."
                }
        
        elif tool_name == "get_agent_health":
            fetch_fn = fetch_functions.get("fetch_agent_health_for_site")
            if fetch_fn:
                df_versions, df_attention = fetch_fn(site_id)
                return {
                    "success": True,
                    "version_distribution": df_versions.to_dict(orient="records") if not df_versions.empty else [],
                    "attention_required": df_attention.to_dict(orient="records") if not df_attention.empty else [],
                    "message": f"Agent health data retrieved for {site_name}."
                }
        
        return {
            "success": False,
            "error": f"Unknown tool: {tool_name}"
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Error executing {tool_name}: {str(e)}"
        }


def format_tool_result_for_display(result: Dict[str, Any], tool_name: str) -> str:
    """
    Format tool execution result for display to user.
    
    Args:
        result: Result dictionary from execute_tool
        tool_name: Name of the tool that was executed
    
    Returns:
        Formatted string for display
    """
    if not result.get("success"):
        return f"❌ Error: {result.get('error', 'Unknown error')}"
    
    output_lines = [f"✅ {result.get('message', 'Query completed.')}"]
    output_lines.append("")
    
    # Format based on tool type
    if tool_name == "list_available_sites":
        output_lines.append("**Available Sites:**")
        for site in result.get("data", []):
            output_lines.append(f"• {site}")
    
    elif tool_name in ["get_blocklisted_hashes", "get_threats", "get_vulnerabilities", "get_endpoints"]:
        data = result.get("data", [])
        if data:
            # Show first few records as a sample
            output_lines.append(f"**Showing first {min(10, len(data))} of {result.get('total_count', len(data))} results:**")
            output_lines.append("")
            
            for i, record in enumerate(data[:10]):
                output_lines.append(f"**{i+1}.** " + " | ".join([f"{k}: {v}" for k, v in list(record.items())[:4]]))
        
        # Show summary if available
        summary = result.get("summary", [])
        if summary:
            output_lines.append("")
            output_lines.append("**Summary:**")
            for item in summary:
                output_lines.append(f"• " + " | ".join([f"{k}: {v}" for k, v in item.items()]))
    
    elif tool_name == "get_agent_health":
        versions = result.get("version_distribution", [])
        if versions:
            output_lines.append("**Agent Versions:**")
            for v in versions:
                output_lines.append(f"• " + " | ".join([f"{k}: {v}" for k, v in v.items()]))
        
        attention = result.get("attention_required", [])
        if attention:
            output_lines.append("")
            output_lines.append("**Attention Required:**")
            for a in attention:
                output_lines.append(f"• " + " | ".join([f"{k}: {v}" for k, v in a.items()]))
    
    return "\n".join(output_lines)
