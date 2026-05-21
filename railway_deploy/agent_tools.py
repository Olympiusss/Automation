"""
SentinelOne AI Query Agent - Tool Definitions and Execution
This module defines the tools available to the AI agent and executes them.
"""

import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional, List
from sentinelone_api import (
    fetch_endpoints_for_site,
    fetch_threats_for_site,
    fetch_risks_for_site,
    fetch_blocklisted_hashes_for_site,
    fetch_all_with_cursor,
    process_vulnerabilities,
    process_agent_stats,
    fetch_alerts_for_site,
    fetch_activities_for_site,
    fetch_threat_details,
    fetch_deep_visibility_events,
    fetch_exclusions_for_site,
    fetch_policies_for_site,
    fetch_sites,
)

# Tool definitions for the LLM
AGENT_TOOLS = [
    {
        "name": "get_blocklisted_hashes",
        "description": "Fetch blocklisted hash restrictions for a specific site. Use count_only=true to get just the total count.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_name": {
                    "type": "string",
                    "description": "Name of the site (e.g., 'Etranzact', 'MU', 'Qore', 'Upfront')"
                },
                "count_only": {
                    "type": "boolean",
                    "description": "If true, return only the count, not the list of hashes. Use for 'how many' questions."
                }
            },
            "required": ["site_name"]
        }
    },
    {
        "name": "get_threats",
        "description": "Fetch threat data for a specific site within a date range. Use count_only=true to get just the total count.",
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
                },
                "count_only": {
                    "type": "boolean",
                    "description": "If true, return only the count, not the list of threats. Use for 'how many' questions."
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
        "name": "get_endpoint_details",
        "description": "Get detailed information about a specific endpoint/host by name. Returns OS type, IP addresses, logged-in user, infection status, agent version, and network details. Use this to investigate a specific machine.",
        "parameters": {
            "type": "object",
            "properties": {
                "endpoint_name": {
                    "type": "string",
                    "description": "Name or partial name of the endpoint/host to look up"
                },
                "site_name": {
                    "type": "string",
                    "description": "Name of the site the endpoint belongs to"
                }
            },
            "required": ["endpoint_name", "site_name"]
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
    },
    {
        "name": "get_alerts",
        "description": "Fetch cloud detection alerts for a specific site. Returns alert rule name, severity, status, affected endpoints, and timestamps.",
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
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: Critical, High, Medium, Low"
                },
                "count_only": {
                    "type": "boolean",
                    "description": "If true, return only the count."
                }
            },
            "required": ["site_name"]
        }
    },
    {
        "name": "get_activities",
        "description": "Fetch audit trail activities for a site. Shows user actions, policy changes, agent events, and response actions taken.",
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
                },
                "count_only": {
                    "type": "boolean",
                    "description": "If true, return only the count."
                }
            },
            "required": ["site_name"]
        }
    },
    {
        "name": "get_threat_forensics",
        "description": "Get detailed forensic data for a specific threat by its ID. Returns MITRE ATT&CK info, threat indicators, file details, classification, mitigation status, and timeline. Use after finding a threat from get_threats.",
        "parameters": {
            "type": "object",
            "properties": {
                "threat_id": {
                    "type": "string",
                    "description": "The SentinelOne threat ID to investigate"
                }
            },
            "required": ["threat_id"]
        }
    },
    {
        "name": "get_site_overview",
        "description": "Get a comprehensive overview of a site's security posture. Returns endpoint count, threat count, alert count, vulnerability summary, and agent health in one call. Use this for site status or health check queries.",
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
        "name": "compare_sites",
        "description": "Compare security posture across multiple sites. Returns side-by-side comparison of endpoints, threats, alerts, and vulnerabilities. Use when user asks about all sites or wants to compare.",
        "parameters": {
            "type": "object",
            "properties": {
                "site_names": {
                    "type": "string",
                    "description": "Comma-separated site names to compare, or 'all' for all sites"
                }
            },
            "required": ["site_names"]
        }
    },
    {
        "name": "get_exclusions",
        "description": "Fetch exclusion/whitelist rules configured for a site. Shows what files, paths, hashes, or processes are excluded from scanning.",
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
    sites_data: list
) -> Dict[str, Any]:
    """
    Execute the requested tool and return results.
    
    Args:
        tool_name: Name of the tool to execute
        params: Parameters for the tool
        sites_data: List of available sites
    
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
            df_hashes, df_summary = fetch_blocklisted_hashes_for_site(site_id)
            total_count = len(df_hashes)
            
            # Check if count_only mode
            count_only = params.get("count_only", False)
            if count_only:
                return {
                    "success": True,
                    "total_count": total_count,
                    "count_only": True,
                    "message": f"There are {total_count} blocklisted hashes on {site_name}."
                }
            
            # Client-side date filtering if dates provided
            start_date = params.get("start_date")
            end_date = params.get("end_date")
            
            if start_date and end_date and not df_hashes.empty and "Created At" in df_hashes.columns:
                try:
                    df_hashes["Created At"] = pd.to_datetime(df_hashes["Created At"], errors="coerce")
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
                    df_hashes = df_hashes[
                        (df_hashes["Created At"] >= start_dt) & 
                        (df_hashes["Created At"] <= end_dt)
                    ]
                except Exception:
                    pass
            
            return {
                "success": True,
                "total_count": total_count,
                "data": df_hashes.head(50).to_dict(orient="records"),
                "summary": df_summary.to_dict(orient="records") if not df_summary.empty else [],
                "message": f"Found {total_count} blocklisted hashes for {site_name}."
            }
        
        elif tool_name == "get_threats":
            start_iso, end_iso = parse_date_range(params["start_date"], params["end_date"])
            threats_data = fetch_threats_for_site(site_id, start_iso, end_iso)
            total_count = len(threats_data) if isinstance(threats_data, list) else 0
            
            count_only = params.get("count_only", False)
            if count_only:
                return {
                    "success": True,
                    "total_count": total_count,
                    "count_only": True,
                    "message": f"There are {total_count} threats on {site_name} from {params['start_date']} to {params['end_date']}."
                }
            
            if isinstance(threats_data, list) and threats_data:
                df_threats = pd.DataFrame(threats_data)
            else:
                df_threats = pd.DataFrame()
            
            return {
                "success": True,
                "total_count": total_count,
                "data": df_threats.head(50).to_dict(orient="records") if not df_threats.empty else [],
                "message": f"Found {total_count} threats for {site_name}."
            }
        
        elif tool_name == "get_vulnerabilities":
            risks_data = fetch_risks_for_site(site_id)
            df_vulns, _, _, df_summary, _ = process_vulnerabilities(risks_data)
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
            all_endpoints = fetch_endpoints_for_site(site_id)
            df_endpoints = pd.DataFrame(all_endpoints) if all_endpoints else pd.DataFrame()
            df_os = df_endpoints["osType"].value_counts().reset_index() if not df_endpoints.empty and "osType" in df_endpoints.columns else pd.DataFrame(columns=["osType", "count"])
            return {
                "success": True,
                "total_count": len(df_endpoints),
                "data": df_endpoints.head(50).to_dict(orient="records"),
                "os_distribution": df_os.to_dict(orient="records") if not df_os.empty else [],
                "message": f"Found {len(df_endpoints)} endpoints for {site_name}."
            }
        
        elif tool_name == "get_agent_health":
            all_agents = fetch_all_with_cursor("agents", {"siteIds": site_id})
            df_versions, df_attention = process_agent_stats(all_agents)
            return {
                "success": True,
                "version_distribution": df_versions.to_dict(orient="records") if not df_versions.empty else [],
                "attention_required": df_attention.to_dict(orient="records") if not df_attention.empty else [],
                "message": f"Agent health data retrieved for {site_name}."
            }
        
        elif tool_name == "get_endpoint_details":
            endpoint_name = params.get("endpoint_name", "")
            all_endpoints = fetch_endpoints_for_site(site_id)
            if isinstance(all_endpoints, tuple):
                all_endpoints = all_endpoints[0] if all_endpoints else []
            if isinstance(all_endpoints, pd.DataFrame):
                all_endpoints = all_endpoints.to_dict(orient="records")
            
            matched = []
            ep_name_lower = endpoint_name.lower()
            for ep in (all_endpoints if isinstance(all_endpoints, list) else []):
                if isinstance(ep, dict):
                    name = str(ep.get("computerName", "")).lower()
                    if ep_name_lower in name or name in ep_name_lower:
                        matched.append({
                            "computerName": ep.get("computerName", "N/A"),
                            "osType": ep.get("osType", "N/A"),
                            "osName": ep.get("osName", "N/A"),
                            "lastIpAddress": ep.get("lastIpAddress", "N/A"),
                            "externalIp": ep.get("externalIp", "N/A"),
                            "lastLoggedInUserName": ep.get("lastLoggedInUserName", "N/A"),
                            "infected": ep.get("infected", False),
                            "isActive": ep.get("isActive", False),
                            "isProtected": ep.get("isProtected", False),
                            "agentVersion": ep.get("agentVersion", "N/A"),
                            "machineType": ep.get("machineType", "N/A"),
                            "domain": ep.get("domain", "N/A"),
                            "groupName": ep.get("groupName", "N/A"),
                            "activeThreats": ep.get("activeThreats", 0),
                            "networkStatus": ep.get("networkStatus", "N/A"),
                            "lastActiveDate": ep.get("lastActiveDate", "N/A"),
                        })
            
            if matched:
                return {
                    "success": True,
                    "total_count": len(matched),
                    "data": matched,
                    "message": f"Found {len(matched)} endpoint(s) matching '{endpoint_name}' on {site_name}."
                }
            else:
                return {
                    "success": True,
                    "total_count": 0,
                    "data": [],
                    "message": f"No endpoints matching '{endpoint_name}' found on {site_name}."
                }
        
        elif tool_name == "get_alerts":
            start_iso, end_iso = None, None
            if params.get("start_date") and params.get("end_date"):
                start_iso, end_iso = parse_date_range(params["start_date"], params["end_date"])
            severity_filter = params.get("severity")
            alerts_data = fetch_alerts_for_site(site_id, start_iso, end_iso, severity_filter)
            total_count = len(alerts_data) if isinstance(alerts_data, list) else 0
            
            count_only = params.get("count_only", False)
            if count_only:
                return {
                    "success": True,
                    "total_count": total_count,
                    "count_only": True,
                    "message": f"There are {total_count} alerts on {site_name}."
                }
            
            # Extract key fields from alerts
            alert_rows = []
            for a in (alerts_data[:50] if isinstance(alerts_data, list) else []):
                if isinstance(a, dict):
                    alert_rows.append({
                        "alertId": a.get("id", "N/A"),
                        "ruleName": a.get("ruleName", a.get("alertName", "N/A")),
                        "severity": a.get("severity", "N/A"),
                        "status": a.get("analystVerdict", a.get("status", "N/A")),
                        "endpoint": a.get("agentComputerName", a.get("endpoint", "N/A")),
                        "createdAt": a.get("createdAt", "N/A"),
                        "description": str(a.get("description", ""))[:200],
                    })
            
            return {
                "success": True,
                "total_count": total_count,
                "data": alert_rows,
                "message": f"Found {total_count} alerts for {site_name}."
            }
        
        elif tool_name == "get_activities":
            start_iso, end_iso = None, None
            if params.get("start_date") and params.get("end_date"):
                start_iso, end_iso = parse_date_range(params["start_date"], params["end_date"])
            activities = fetch_activities_for_site(site_id, start_iso, end_iso)
            total_count = len(activities) if isinstance(activities, list) else 0
            
            count_only = params.get("count_only", False)
            if count_only:
                return {
                    "success": True,
                    "total_count": total_count,
                    "count_only": True,
                    "message": f"There are {total_count} activities on {site_name}."
                }
            
            activity_rows = []
            for act in (activities[:50] if isinstance(activities, list) else []):
                if isinstance(act, dict):
                    activity_rows.append({
                        "activityType": act.get("activityType", "N/A"),
                        "description": str(act.get("primaryDescription", act.get("description", "")))[:300],
                        "user": act.get("userId", act.get("userName", "N/A")),
                        "createdAt": act.get("createdAt", "N/A"),
                        "siteName": act.get("siteName", site_name),
                    })
            
            return {
                "success": True,
                "total_count": total_count,
                "data": activity_rows,
                "message": f"Found {total_count} activities for {site_name}."
            }
        
        elif tool_name == "get_threat_forensics":
            threat_id = params.get("threat_id", "")
            if not threat_id:
                return {"success": False, "error": "threat_id is required."}
            
            details = fetch_threat_details(threat_id)
            if not details:
                return {
                    "success": False,
                    "error": f"Could not fetch details for threat ID {threat_id}."
                }
            
            # Extract the most useful forensic fields
            threat_info = details if isinstance(details, dict) else {}
            ti = threat_info.get("threatInfo", threat_info)
            agent_info = threat_info.get("agentRealtimeInfo", threat_info.get("agentDetectionInfo", {}))
            indicators = threat_info.get("indicators", [])
            mitre = threat_info.get("mitreTactics", threat_info.get("mitre", []))
            
            forensic = {
                "threatId": threat_id,
                "threatName": ti.get("threatName", ti.get("classification", "N/A")),
                "classification": ti.get("classification", "N/A"),
                "classificationSource": ti.get("classificationSource", "N/A"),
                "confidenceLevel": ti.get("confidenceLevel", "N/A"),
                "severity": ti.get("analystVerdictDescription", ti.get("severity", "N/A")),
                "mitigationStatus": ti.get("mitigationStatus", ti.get("mitigationStatusDescription", "N/A")),
                "incidentStatus": ti.get("incidentStatus", ti.get("incidentStatusDescription", "N/A")),
                "filePath": ti.get("filePath", "N/A"),
                "fileHash": ti.get("sha256", ti.get("md5", "N/A")),
                "processName": ti.get("originatorProcess", "N/A"),
                "initiatedBy": ti.get("initiatedBy", "N/A"),
                "detectedAt": ti.get("createdAt", ti.get("identifiedAt", "N/A")),
                "endpoint": agent_info.get("agentComputerName", agent_info.get("computerName", "N/A")),
                "endpointOS": agent_info.get("agentOsType", agent_info.get("osType", "N/A")),
                "endpointIP": agent_info.get("agentLastLoggedInUpn", "N/A"),
                "indicators": indicators[:10] if isinstance(indicators, list) else [],
                "mitreTactics": mitre[:10] if isinstance(mitre, list) else [],
            }
            
            return {
                "success": True,
                "data": forensic,
                "message": f"Forensic details retrieved for threat {threat_id}."
            }
        
        elif tool_name == "get_site_overview":
            # Aggregate multiple data points for a holistic site view
            endpoints = fetch_endpoints_for_site(site_id)
            ep_count = len(endpoints) if isinstance(endpoints, list) else 0
            
            # Get recent threats (last 30 days)
            now = datetime.utcnow()
            thirty_days_ago = now - timedelta(days=30)
            start_iso = thirty_days_ago.strftime("%Y-%m-%dT00:00:00Z")
            end_iso = now.strftime("%Y-%m-%dT23:59:59Z")
            
            threats = fetch_threats_for_site(site_id, start_iso, end_iso)
            threat_count = len(threats) if isinstance(threats, list) else 0
            
            # Count critical threats
            critical_threats = 0
            if isinstance(threats, list):
                for t in threats:
                    if isinstance(t, dict):
                        sev = str(t.get("threatInfo", t).get("analystVerdictDescription",
                                  t.get("severity", ""))).lower()
                        if "critical" in sev:
                            critical_threats += 1
            
            alerts = fetch_alerts_for_site(site_id, start_iso, end_iso)
            alert_count = len(alerts) if isinstance(alerts, list) else 0
            
            risks = fetch_risks_for_site(site_id)
            vuln_count = len(risks) if isinstance(risks, list) else 0
            
            # Agent health
            df_versions, df_attention = process_agent_stats(endpoints if isinstance(endpoints, list) else [])
            
            return {
                "success": True,
                "data": {
                    "site_name": site_name,
                    "total_endpoints": ep_count,
                    "threats_last_30d": threat_count,
                    "critical_threats_last_30d": critical_threats,
                    "alerts_last_30d": alert_count,
                    "total_vulnerabilities": vuln_count,
                    "agent_versions": df_versions.to_dict(orient="records") if not df_versions.empty else [],
                    "agents_needing_attention": df_attention.to_dict(orient="records") if not df_attention.empty else [],
                },
                "message": f"Site overview for {site_name}: {ep_count} endpoints, {threat_count} threats (last 30d), {alert_count} alerts, {vuln_count} vulnerabilities."
            }
        
        elif tool_name == "compare_sites":
            site_names_str = params.get("site_names", "all")
            
            if site_names_str.lower().strip() == "all":
                target_sites = sites_data
            else:
                requested_names = [n.strip() for n in site_names_str.split(",")]
                target_sites = []
                for rn in requested_names:
                    sid = get_site_id_by_name(rn, sites_data)
                    if sid:
                        target_sites.append({"name": rn, "id": sid})
            
            now = datetime.utcnow()
            thirty_days_ago = now - timedelta(days=30)
            start_iso = thirty_days_ago.strftime("%Y-%m-%dT00:00:00Z")
            end_iso = now.strftime("%Y-%m-%dT23:59:59Z")
            
            comparison = []
            for s in (target_sites if isinstance(target_sites, list) else []):
                if isinstance(s, dict):
                    s_name = s.get("name", "Unknown")
                    s_id = s.get("id", "")
                    if not s_id:
                        continue
                    
                    eps = fetch_endpoints_for_site(s_id)
                    threats = fetch_threats_for_site(s_id, start_iso, end_iso)
                    alerts = fetch_alerts_for_site(s_id, start_iso, end_iso)
                    
                    comparison.append({
                        "site": s_name,
                        "endpoints": len(eps) if isinstance(eps, list) else 0,
                        "threats_30d": len(threats) if isinstance(threats, list) else 0,
                        "alerts_30d": len(alerts) if isinstance(alerts, list) else 0,
                    })
            
            return {
                "success": True,
                "data": comparison,
                "total_sites": len(comparison),
                "message": f"Compared {len(comparison)} sites."
            }
        
        elif tool_name == "get_exclusions":
            exclusions = fetch_exclusions_for_site(site_id)
            total_count = len(exclusions) if isinstance(exclusions, list) else 0
            
            excl_rows = []
            for ex in (exclusions[:50] if isinstance(exclusions, list) else []):
                if isinstance(ex, dict):
                    excl_rows.append({
                        "type": ex.get("type", "N/A"),
                        "value": ex.get("value", "N/A"),
                        "osType": ex.get("osType", "N/A"),
                        "description": str(ex.get("description", ""))[:200],
                        "mode": ex.get("mode", "N/A"),
                        "source": ex.get("source", "N/A"),
                        "createdAt": ex.get("createdAt", "N/A"),
                    })
            
            return {
                "success": True,
                "total_count": total_count,
                "data": excl_rows,
                "message": f"Found {total_count} exclusions for {site_name}."
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
    
    elif tool_name in ["get_blocklisted_hashes", "get_threats", "get_vulnerabilities", "get_endpoints", "get_endpoint_details"]:
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
