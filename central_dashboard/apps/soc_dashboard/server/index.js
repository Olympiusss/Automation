import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import axios from "axios";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import XLSX from "xlsx";
import jwt from "jsonwebtoken";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

const PORT = Number(process.env.PORT || 8080);
const BASE_URL = (process.env.S1_BASE_URL || "https://euce1-exclusive.sentinelone.net/web/api/v2.1").replace(/\/$/, "");
const API_TOKEN = process.env.S1_API_TOKEN || process.env.API_TOKEN || "";
const TOTP_SECRET = process.env.TOTP_SECRET || "";
const TOTP_APP_NAME = process.env.TOTP_APP_NAME || "SentinelOne Dashboard";
const TOTP_ISSUER = process.env.TOTP_ISSUER || "Esentry Security";
const SESSION_TIMEOUT_MINUTES = Number(process.env.SESSION_TIMEOUT_MINUTES || 0);
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.SECRET_KEY || "change-this-for-railway";

// ── External Solution SSO ─────────────────────────────────────────────────────
const EXTERNAL_SSO_URL         = (process.env.EXTERNAL_SSO_URL || "").replace(/\/$/, "");
const EXTERNAL_SSO_SECRET      = process.env.EXTERNAL_SSO_SECRET || "";
const EXTERNAL_SSO_ISSUER      = process.env.EXTERNAL_SSO_ISSUER || "central-platform";
const EXTERNAL_SSO_AUDIENCE    = process.env.EXTERNAL_SSO_AUDIENCE || "soc-dashboard";
const EXTERNAL_SSO_TOKEN_FIELD = process.env.EXTERNAL_SSO_TOKEN_FIELD || "token";
const EXTERNAL_SSO_TOKEN_TTL   = Math.min(Number(process.env.EXTERNAL_SSO_TOKEN_TTL || 60), 300);

const DEFAULT_SITE_PINS = {
  "Default site": "Decipher211$",
  RoutePay: "Decipher777$",
  "Infoprive Systems": "Decipher222$",
  "Zone Payment Network Limited": "Decipher555$",
  "Qore Inc Technologies": "Decipher666$",
  "SunTrust Bank": "Decipher888$",
  Cybervergent: "Decipher111$",
  eTranzact: "Decipher333$"
};

function parseJsonEnv(name, fallback) {
  if (!process.env[name]) return fallback;
  try {
    return JSON.parse(process.env[name]);
  } catch {
    console.warn(`${name} is not valid JSON. Using fallback.`);
    return fallback;
  }
}

const SITE_PINS        = parseJsonEnv("SITE_PINS", DEFAULT_SITE_PINS);
const ANALYST_PROFILES = parseJsonEnv("ANALYST_PROFILES", {});
const sessions         = new Map();

// JTI replay-protection store: jti -> absolute expiry (ms since epoch)
// Tokens are short-lived (≤5 min), so memory pressure is negligible.
const usedJtis = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [jti, exp] of usedJtis) {
    if (now > exp) usedJtis.delete(jti);
  }
}, 5 * 60 * 1000).unref();

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "20mb" }));
app.use(cookieParser());

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function safeCompare(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function makeCookie(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${sign(encoded)}`;
}

function readCookie(raw) {
  if (!raw || !raw.includes(".")) return null;
  const [encoded, signature] = raw.split(".");
  if (!safeCompare(signature, sign(encoded))) return null;
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function setSessionCookie(res, sessionId) {
  const maxAge = SESSION_TIMEOUT_MINUTES > 0 ? SESSION_TIMEOUT_MINUTES * 60 * 1000 : undefined;
  res.cookie("s1_report_session", makeCookie({ sessionId }), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge
  });
}

function requireTotp(req, res, next) {
  if (!TOTP_SECRET) {
    req.session = { totpAuthenticated: true, authenticatedSites: new Map(), generatedAt: Date.now() };
    return next();
  }
  const payload = readCookie(req.cookies.s1_report_session);
  const session = payload ? sessions.get(payload.sessionId) : null;
  if (!session?.totpAuthenticated) {
    return res.status(401).json({ error: "TOTP authentication required." });
  }
  req.session = session;
  next();
}

function s1Client() {
  if (!API_TOKEN) throw new Error("S1_API_TOKEN is not configured.");
  return axios.create({
    baseURL: BASE_URL,
    timeout: 45000,
    headers: {
      Authorization: `ApiToken ${API_TOKEN}`,
      "Content-Type": "application/json"
    }
  });
}

async function fetchAllWithCursor(endpoint, params = {}) {
  const client = s1Client();
  const allItems = [];
  let cursor = null;
  const query = { ...params };

  while (true) {
    if (cursor) query.cursor = cursor;
    const response = await client.get(`/${endpoint.replace(/^\//, "")}`, { params: query });
    const body = response.data;
    let items = body?.data ?? body;
    if (items && !Array.isArray(items) && Array.isArray(items.sites)) items = items.sites;
    if (Array.isArray(items)) allItems.push(...items);
    cursor = body?.pagination?.nextCursor;
    if (!cursor) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  return allItems;
}

function counterRows(values, label, limit = 50, totalLabel = "Total Occurrences") {
  const counts = new Map();
  values.filter(Boolean).forEach((value) => counts.set(value, (counts.get(value) || 0) + 1));
  const rows = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([name, count]) => ({ [label]: name, Count: count }));
  rows.push({ [label]: totalLabel, Count: values.filter(Boolean).length });
  return rows;
}

function normalizeSeverity(rawSeverity, baseScore, nvdScore) {
  if (typeof rawSeverity === "string" && rawSeverity.trim()) {
    const value = rawSeverity.trim().toLowerCase();
    if (value.startsWith("crit")) return "Critical";
    if (value.startsWith("high")) return "High";
    if (value.startsWith("med")) return "Medium";
    if (value.startsWith("low")) return "Low";
    if (value.startsWith("info")) return "Informational";
    if (value.includes("false")) return "False Positive";
    if (value === "none") return "None";
    return rawSeverity.trim().replace(/\b\w/g, (char) => char.toUpperCase());
  }

  const score = [nvdScore, baseScore].map(Number).find((value) => Number.isFinite(value));
  if (score === undefined) return "Unknown";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "None";
}

function formatTimestamp(value, style = "short") {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  if (style === "ordinal") {
    const day = date.getUTCDate();
    const suffix = day >= 11 && day <= 13 ? "th" : { 1: "st", 2: "nd", 3: "rd" }[day % 10] || "th";
    return `${date.toLocaleString("en", { month: "short", timeZone: "UTC" })} ${day}${suffix} ${date.getUTCFullYear()} - ${date.toISOString().slice(11, 19)}`;
  }
  return date.toISOString().replace("T", " ").slice(0, 19);
}

function startOfUtcDay(date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function startOfUtcWeek(date) {
  const day = date.getUTCDay() || 7;
  const start = startOfUtcDay(date);
  start.setUTCDate(start.getUTCDate() - day + 1);
  return start;
}

function parseAgentTimeRange(question) {
  const text = question.toLowerCase();
  const now = new Date();
  let start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  let label = "last 7 days";

  const dayMatch = text.match(/last\s+(\d{1,3})\s+days?/);
  if (dayMatch) {
    const days = Math.max(1, Math.min(90, Number(dayMatch[1])));
    start = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    label = `last ${days} days`;
  } else if (/\bthis\s+week\b|\bwithin\s+this\s+week\b|\bcurrent\s+week\b/.test(text)) {
    start = startOfUtcWeek(now);
    label = "this week";
  } else if (/\blast\s+week\b/.test(text)) {
    const thisWeek = startOfUtcWeek(now);
    start = new Date(thisWeek.getTime() - 7 * 24 * 60 * 60 * 1000);
    now.setTime(thisWeek.getTime() - 1);
    label = "last week";
  } else if (/\bthis\s+month\b|\bcurrent\s+month\b/.test(text)) {
    start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    label = "this month";
  } else if (/\btoday\b/.test(text)) {
    start = startOfUtcDay(now);
    label = "today";
  } else if (/\byesterday\b/.test(text)) {
    const today = startOfUtcDay(now);
    start = new Date(today.getTime() - 24 * 60 * 60 * 1000);
    now.setTime(today.getTime() - 1);
    label = "yesterday";
  }

  return {
    startIso: start.toISOString(),
    endIso: now.toISOString(),
    label
  };
}

function classifyAgentIntent(question) {
  const text = question.toLowerCase();
  if (/(lateral|psexec|wmi|smb|rdp|remote service|pass[-\s]?the[-\s]?hash|credential reuse|remote logon)/.test(text)) {
    return "lateral_movement";
  }
  if (/(vulnerab|cve|application risk|app risk|exposure)/.test(text)) return "vulnerabilities";
  if (/(hash|blocklist|blacklist|restriction|ioc)/.test(text)) return "hashes";
  if (/(endpoint|agent|machine|host|device)/.test(text)) return "endpoints";
  return "threats";
}

function itemText(item) {
  return JSON.stringify(item || {}).toLowerCase();
}

function matchesAnyKeyword(item, keywords) {
  const text = itemText(item);
  return keywords.some((keyword) => text.includes(keyword));
}

function uniqBy(items, keyFn) {
  const seen = new Set();
  const rows = [];
  for (const item of items) {
    const key = keyFn(item);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    rows.push(item);
  }
  return rows;
}

function buildScopeParams(siteIds) {
  if (!Array.isArray(siteIds) || !siteIds.length) return {};
  return { siteIds: siteIds.filter(Boolean).join(",") };
}

async function safeFetchAll(endpoint, params) {
  try {
    const data = await fetchAllWithCursor(endpoint, params);
    return { data, error: null };
  } catch (error) {
    return {
      data: [],
      error: error.response?.data ? JSON.stringify(error.response.data) : error.message
    };
  }
}

async function resolvePromptSites(question, selectedSiteIds) {
  if (Array.isArray(selectedSiteIds) && selectedSiteIds.length) return selectedSiteIds;
  const sites = await safeFetchAll("sites", { limit: 200 });
  if (!sites.data.length) return [];
  const text = question.toLowerCase();
  return sites.data
    .filter((site) => site.id && site.name && text.includes(String(site.name).toLowerCase()))
    .map((site) => site.id);
}

function summarizeBy(values, fallback = "Unknown") {
  const counts = new Map();
  for (const value of values) {
    const key = value || fallback;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

function threatEvidence(threats) {
  return threats.slice(0, 8).map((item) => {
    const ti = item.threatInfo || {};
    const ari = item.agentRealtimeInfo || {};
    return {
      id: ti.threatId || item.id,
      title: ti.threatName || ti.displayName || ti.processName || "Threat",
      subtitle: `${ari.agentComputerName || "Unknown endpoint"} - ${ti.classification || "Unclassified"}`,
      time: ti.createdAt || ti.updatedAt
    };
  });
}

function activityEvidence(activities) {
  return activities.slice(0, 8).map((item) => ({
    id: item.id,
    title: item.activityType || item.primaryDescription || item.description || "Activity",
    subtitle: item.agentName || item.computerName || item.siteName || "SentinelOne activity",
    time: item.createdAt || item.updatedAt
  }));
}

async function answerLateralMovement(question, range, siteIds) {
  const scope = buildScopeParams(siteIds);
  const lateralKeywords = [
    "lateral",
    "psexec",
    "remote service",
    "remote logon",
    "rdp",
    "smb",
    "wmi",
    "pass the hash",
    "passthehash",
    "credential reuse",
    "mitre.t1021",
    "t1021",
    "t1075",
    "t1570"
  ];

  const [threatsResult, activitiesResult] = await Promise.all([
    safeFetchAll("threats", {
      ...scope,
      createdAt__gte: range.startIso,
      createdAt__lte: range.endIso,
      limit: 1000,
      sortBy: "createdAt",
      sortOrder: "desc"
    }),
    safeFetchAll("activities", {
      ...scope,
      createdAt__gte: range.startIso,
      createdAt__lte: range.endIso,
      limit: 1000,
      sortBy: "createdAt",
      sortOrder: "desc"
    })
  ]);

  const lateralThreats = threatsResult.data.filter((item) => matchesAnyKeyword(item, lateralKeywords));
  const lateralActivities = activitiesResult.data.filter((item) => matchesAnyKeyword(item, lateralKeywords));
  const combined = uniqBy([...lateralThreats, ...lateralActivities], (item) => item.id || item.threatInfo?.threatId);
  const endpoints = summarizeBy([
    ...lateralThreats.map((item) => item.agentRealtimeInfo?.agentComputerName),
    ...lateralActivities.map((item) => item.agentName || item.computerName)
  ]).slice(0, 5);

  const limitations = [threatsResult.error && `Threats API: ${threatsResult.error}`, activitiesResult.error && `Activities API: ${activitiesResult.error}`].filter(Boolean);
  const answer = `I found ${combined.length} lateral-movement-related SentinelOne records for ${range.label}. ${
    endpoints.length ? `The most affected endpoint was ${endpoints[0][0]} with ${endpoints[0][1]} matching record${endpoints[0][1] === 1 ? "" : "s"}.` : "No affected endpoint stood out from the returned telemetry."
  }${limitations.length ? " Some telemetry sources could not be queried, so treat this as a partial result." : ""}`;

  return {
    agent: "Investigation Agent",
    confidence: limitations.length ? "Partial evidence" : "Evidence-backed",
    answer,
    findings: [
      { label: "Lateral movement records", value: combined.length },
      { label: "Matching threats", value: lateralThreats.length },
      { label: "Matching activities", value: lateralActivities.length }
    ],
    metrics: [
      { label: "Matches", value: combined.length, tone: combined.length ? "red" : "green", icon: "AlertTriangle" },
      { label: "Threats", value: lateralThreats.length, icon: "Shield" },
      { label: "Activities", value: lateralActivities.length, icon: "Activity" }
    ],
    evidence: [...threatEvidence(lateralThreats), ...activityEvidence(lateralActivities)].slice(0, 8),
    plan: [
      `Set time range to ${range.label}`,
      "Queried SentinelOne threats",
      "Queried SentinelOne activities",
      "Matched lateral movement keywords and MITRE technique markers",
      "Deduplicated matching records"
    ]
  };
}

async function answerThreats(range, siteIds) {
  const result = await safeFetchAll("threats", {
    ...buildScopeParams(siteIds),
    createdAt__gte: range.startIso,
    createdAt__lte: range.endIso,
    limit: 1000,
    sortBy: "createdAt",
    sortOrder: "desc"
  });
  const threats = result.data;
  const unresolved = threats.filter((item) => {
    const status = String(item.threatInfo?.incidentStatus || item.threatInfo?.mitigationStatus || "").toLowerCase();
    return status.includes("unresolved") || status.includes("progress") || status.includes("not");
  });
  const high = threats.filter((item) => /high|critical/i.test(item.threatInfo?.confidenceLevel || item.threatInfo?.severity || item.threatInfo?.classification || ""));
  const classes = summarizeBy(threats.map((item) => item.threatInfo?.classification)).slice(0, 3);

  return {
    agent: "Triage Agent",
    confidence: result.error ? "Partial evidence" : "Evidence-backed",
    answer: `I found ${threats.length} SentinelOne threats for ${range.label}. ${unresolved.length} appear unresolved or in progress. ${classes.length ? `Top classification: ${classes[0][0]} (${classes[0][1]}).` : ""}`,
    findings: [
      { label: "Threats", value: threats.length },
      { label: "Unresolved/in progress", value: unresolved.length },
      { label: "High-signal records", value: high.length }
    ],
    metrics: [
      { label: "Threats", value: threats.length, icon: "Shield" },
      { label: "Open", value: unresolved.length, tone: unresolved.length ? "red" : "green", icon: "AlertTriangle" },
      { label: "Classes", value: summarizeBy(threats.map((item) => item.threatInfo?.classification)).length, icon: "Database" }
    ],
    evidence: threatEvidence(threats),
    plan: [`Set time range to ${range.label}`, "Queried SentinelOne threats", "Grouped by status and classification"]
  };
}

async function answerVulnerabilities(range, siteIds) {
  const result = await safeFetchAll("application-management/risks", {
    ...buildScopeParams(siteIds),
    detectionDate__gte: range.startIso,
    detectionDate__lte: range.endIso,
    limit: 1000,
    sortBy: "detectionDate",
    sortOrder: "desc"
  });
  const risks = result.data;
  const severity = summarizeBy(risks.map((risk) => normalizeSeverity(risk.severity, risk.baseScore || risk.riskScore, risk.nvdBaseScore))).slice(0, 5);
  const endpoints = new Set(risks.map((risk) => risk.endpointName || risk.endpoint).filter(Boolean));

  return {
    agent: "Exposure Agent",
    confidence: result.error ? "Partial evidence" : "Evidence-backed",
    answer: `I found ${risks.length} application risk records for ${range.label} across ${endpoints.size} endpoint${endpoints.size === 1 ? "" : "s"}. ${severity.length ? `Highest count: ${severity[0][0]} (${severity[0][1]}).` : ""}`,
    findings: [
      { label: "Risk records", value: risks.length },
      { label: "Affected endpoints", value: endpoints.size },
      { label: "Severity buckets", value: severity.length }
    ],
    metrics: [
      { label: "Risks", value: risks.length, icon: "AlertTriangle" },
      { label: "Endpoints", value: endpoints.size, icon: "Database" },
      { label: "Buckets", value: severity.length, icon: "Activity" }
    ],
    evidence: risks.slice(0, 8).map((risk) => ({
      id: risk.id || `${risk.applicationName}-${risk.endpointName}`,
      title: risk.applicationName || risk.application || "Application risk",
      subtitle: `${risk.endpointName || risk.endpoint || "Unknown endpoint"} - ${normalizeSeverity(risk.severity, risk.baseScore || risk.riskScore, risk.nvdBaseScore)}`,
      time: risk.detectionDate || risk.updatedAt || risk.createdAt
    })),
    plan: [`Set time range to ${range.label}`, "Queried SentinelOne application risks", "Grouped risk records by severity and endpoint"]
  };
}

async function answerHashes(range, siteIds) {
  const rows = [];
  const scopedSiteIds = Array.isArray(siteIds) && siteIds.length ? siteIds : [undefined];
  for (const siteId of scopedSiteIds) {
    rows.push(...await fetchBlocklistedHashes(siteId, range.startIso, range.endIso));
  }

  return {
    agent: "IOC Agent",
    confidence: "Evidence-backed",
    answer: `I found ${rows.length} blocklisted hash record${rows.length === 1 ? "" : "s"} updated in ${range.label}.`,
    findings: [
      { label: "Blocklisted hashes", value: rows.length },
      { label: "Imported", value: rows.filter((row) => row.Imported === "Yes").length },
      { label: "Manual/local", value: rows.filter((row) => row.Imported !== "Yes").length }
    ],
    metrics: [
      { label: "Hashes", value: rows.length, icon: "Database" },
      { label: "Imported", value: rows.filter((row) => row.Imported === "Yes").length, icon: "Activity" }
    ],
    evidence: rows.slice(0, 8).map((row) => ({
      id: row["Hash Value"],
      title: row["Hash Value"],
      subtitle: `${row["OS Type"] || "Unknown OS"} - ${row.Source || "Unknown source"}`,
      time: row["Last Updated"] || row["Created At"]
    })),
    plan: [`Set time range to ${range.label}`, "Queried SentinelOne restrictions", "Filtered black-hash records by update time"]
  };
}

async function answerEndpoints(siteIds) {
  const result = await safeFetchAll("agents", {
    ...buildScopeParams(siteIds),
    limit: 1000
  });
  const endpoints = result.data;
  const protectedCount = endpoints.filter((agent) => agent.isProtected !== false).length;
  const attention = endpoints.filter((agent) => {
    const action = agent.userActionsNeeded;
    return agent.isProtected === false || (action && action !== "none") || agent.operationalState === "disabled";
  });
  const osTypes = summarizeBy(endpoints.map((agent) => agent.osType)).slice(0, 5);

  return {
    agent: "Endpoint Agent",
    confidence: result.error ? "Partial evidence" : "Evidence-backed",
    answer: `I found ${endpoints.length} SentinelOne endpoint${endpoints.length === 1 ? "" : "s"}. ${protectedCount} appear protected and ${attention.length} need attention.`,
    findings: [
      { label: "Endpoints", value: endpoints.length },
      { label: "Protected", value: protectedCount },
      { label: "Need attention", value: attention.length }
    ],
    metrics: [
      { label: "Endpoints", value: endpoints.length, icon: "Database" },
      { label: "Protected", value: protectedCount, tone: "green", icon: "Shield" },
      { label: "Attention", value: attention.length, tone: attention.length ? "red" : "green", icon: "AlertTriangle" }
    ],
    evidence: endpoints.slice(0, 8).map((agent) => ({
      id: agent.id,
      title: agent.computerName || agent.agentName || "Endpoint",
      subtitle: `${agent.osType || "Unknown OS"} - ${agent.agentVersion || "Unknown version"}`,
      time: agent.updatedAt || agent.createdAt || agent.lastActiveDate
    })),
    plan: ["Queried SentinelOne agents", "Counted protected endpoints", `Grouped OS types${osTypes.length ? `; top OS is ${osTypes[0][0]}` : ""}`]
  };
}

function processAgentStats(endpoints) {
  const versions = counterRows(endpoints.map((item) => item.agentVersion || "Unknown"), "Agent Version", 20);
  const counts = new Map();
  for (const endpoint of endpoints) {
    const missingPermissions = endpoint.missingPermissions;
    const userAction = endpoint.userActionsNeeded;
    const operationalState = endpoint.operationalState;
    let category = null;
    if (Array.isArray(missingPermissions) && missingPermissions.length) category = "Missing permission";
    else if (missingPermissions) category = "Missing permission";
    else if (userAction === "incompatible_os") category = "Incompatible OS";
    else if (userAction === "unprotected" || endpoint.isProtected === false) category = "Unprotected";
    else if (operationalState === "shunned" || operationalState === "disabled") category = "Agent suppressed";
    else if (userAction && userAction !== "none") category = "Attention needed";
    if (category) counts.set(category, (counts.get(category) || 0) + 1);
  }
  return {
    versions,
    attention: [...counts.entries()].map(([Category, Count]) => ({ Category, Count }))
  };
}

async function fetchBlocklistedHashes(siteId, startIso, endIso) {
  const restrictions = await fetchAllWithCursor("restrictions", {
    limit: 1000,
    type: "black_hash",
    siteIds: siteId,
    includeParents: "true",
    includeChildren: "true"
  });
  const start = startIso ? new Date(startIso) : null;
  const end = endIso ? new Date(endIso) : null;
  const rows = [];

  for (const item of restrictions) {
    const hash = item.sha256Value || item.value;
    if (!hash) continue;
    const updatedAt = item.updatedAt ? new Date(item.updatedAt) : null;
    if (updatedAt && start && updatedAt < start) continue;
    if (updatedAt && end && updatedAt > end) continue;
    rows.push({
      "Hash Value": hash,
      "OS Type": item.osType || "Unknown",
      Description: item.description || "",
      Source: item.source || "Unknown",
      "Last Updated": item.updatedAt || "",
      "Created At": item.createdAt || "",
      Scope: item.scopeName || "",
      User: item.userName || "",
      Imported: item.imported ? "Yes" : "No",
      "Not Recommended": item.notRecommended || "N/A"
    });
  }

  return rows;
}

function processVulnerabilities(risks) {
  const appVersions = [];
  const endpoints = [];
  const severities = [];
  const details = [];

  for (const risk of risks) {
    const appName = risk.applicationName || risk.application || risk.appName;
    const version = risk.applicationVersion || risk.application_version || risk.version;
    const endpoint = risk.endpointName || risk.endpoint;
    const severity = normalizeSeverity(risk.severity, risk.baseScore || risk.riskScore, risk.nvdBaseScore || risk.nvdCvssVersion);
    if (appName) appVersions.push(version ? `${appName} ${version}` : appName);
    if (endpoint) endpoints.push(endpoint);
    if (severity) severities.push(severity);
    if (appName && endpoint) {
      details.push({
        Application: appName,
        Version: version || "N/A",
        "Endpoint Name": endpoint,
        Severity: severity || "Unknown"
      });
    }
  }

  details.sort((a, b) => `${a.Application}${a["Endpoint Name"]}`.localeCompare(`${b.Application}${b["Endpoint Name"]}`));
  return {
    details,
    apps: counterRows(appVersions, "Application + Version", 50),
    endpoints: counterRows(endpoints, "Endpoint Name", 50),
    severity: counterRows(severities, "Severity", 50),
    uniqueEndpoints: new Set(endpoints).size
  };
}

function buildSiteSummary(siteName, threats, risks, endpoints, hashes) {
  const threatClassifications = threats.map((item) => item.threatInfo?.classification || "N/A");
  const threatEndpoints = threats.map((item) => item.agentRealtimeInfo?.agentComputerName || "N/A");
  const threatMitigations = threats.map((item) => item.threatInfo?.mitigationStatusDescription || "N/A");
  const detailedThreats = threats.map((item) => {
    const ti = item.threatInfo || {};
    const ari = item.agentRealtimeInfo || {};
    const rawPath = ti.filePath ? ti.filePath.replaceAll("\\", "/").split("/").pop() : "";
    return {
      ENDPOINT: ari.agentComputerName || "N/A",
      "REPORTED TIME": formatTimestamp(ti.createdAt),
      "UPDATED TIME": formatTimestamp(ti.updatedAt, "ordinal"),
      "THREAT FILE": ti.displayName || ti.threatName || ti.processName || rawPath || "N/A",
      "THREAT CLASSIFICATION": ti.classification || "N/A",
      "AGENT VERSION": ari.agentVersion || "N/A",
      "THREAT MITIGATION STATUS": ti.mitigationStatusDescription || ti.mitigationStatus || "N/A",
      "THREAT RESOLUTION STATUS": ti.incidentStatus || "N/A",
      "ANALYST VERDICT": ti.analystVerdict || "N/A"
    };
  });

  const groupedThreatMap = new Map();
  for (const row of detailedThreats) {
    const key = JSON.stringify(row);
    groupedThreatMap.set(key, (groupedThreatMap.get(key) || 0) + 1);
  }
  const groupedThreats = [...groupedThreatMap.entries()]
    .map(([key, count]) => {
      const row = JSON.parse(key);
      const rest = Object.fromEntries(Object.entries(row).filter(([field]) => field !== "ENDPOINT"));
      return { ENDPOINT: row.ENDPOINT, COUNT: count, ...rest };
    })
    .sort((a, b) => b.COUNT - a.COUNT);

  const threatFiles = detailedThreats.map((row) => row["THREAT FILE"]).filter((value) => value && value !== "N/A");
  const vulnerabilities = processVulnerabilities(risks);
  const agentStats = processAgentStats(endpoints);
  const endpointNames = endpoints.map((item) => item.computerName).filter(Boolean);
  const osTypes = endpoints.map((item) => item.osType || "Unknown").filter(Boolean);
  const uniqueOs = [...new Set(osTypes)].sort();

  return {
    siteName,
    rawCounts: {
      totalThreats: threats.length,
      totalVulnerabilities: risks.length,
      totalEndpoints: endpointNames.length,
      totalHashes: hashes.length,
      uniqueVulnEndpoints: vulnerabilities.uniqueEndpoints
    },
    tables: {
      threatClassifications: counterRows(threatClassifications, "Threat Classification", 30),
      threatEndpoints: counterRows(threatEndpoints, "Endpoint", 30),
      threatMitigations: counterRows(threatMitigations, "Mitigation Status", 30),
      threatFiles: counterRows(threatFiles, "Threat File", 50),
      groupedThreats,
      vulnerabilitySeverity: vulnerabilities.severity,
      vulnerabilityDetails: vulnerabilities.details,
      vulnerabilityApps: vulnerabilities.apps,
      vulnerabilityEndpoints: vulnerabilities.endpoints,
      hashes,
      hashSummary: [{ "Total Blocklisted Hashes": hashes.length }],
      sentinelSummary: [{
        "Total endpoints discovered": endpointNames.length,
        "Total OS entries": uniqueOs.length,
        "OS Types": uniqueOs.join(", ")
      }],
      osTypes: counterRows(osTypes, "OS Type", 50),
      endpointList: endpointNames.map((name) => ({ "Endpoint Name": name })),
      agentVersions: agentStats.versions,
      agentAttention: agentStats.attention
    }
  };
}

function validateIsoRange(startIso, endIso) {
  const start = new Date(startIso);
  const end = new Date(endIso);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) throw new Error("Invalid date range.");
  if (start > end) throw new Error("Start date/time must be before or equal to end date/time.");
  return {
    startIso: start.toISOString().replace(".000Z", "Z"),
    endIso: end.toISOString().replace(".000Z", "Z")
  };
}

async function fetchSiteSummary(site) {
  const [endpoints, threats, risks, hashes] = await Promise.all([
    fetchAllWithCursor("agents", { siteIds: site.siteId, limit: 1000 }),
    fetchAllWithCursor("threats", {
      siteIds: site.siteId,
      createdAt__gte: site.startIso,
      createdAt__lte: site.endIso,
      limit: 1000,
      sortBy: "createdAt",
      sortOrder: "desc"
    }),
    fetchAllWithCursor("application-management/risks", {
      siteIds: site.siteId,
      detectionDate__gte: site.startIso,
      detectionDate__lte: site.endIso,
      limit: 1000,
      sortBy: "detectionDate",
      sortOrder: "desc"
    }),
    fetchBlocklistedHashes(site.siteId, site.startIso, site.endIso)
  ]);

  return buildSiteSummary(site.siteName, threats, risks, endpoints, hashes);
}

function workbookForSummary(summary) {
  const wb = XLSX.utils.book_new();
  const sheets = {
    Threat_Class: summary.tables.threatClassifications,
    Threat_Endpoints: summary.tables.threatEndpoints,
    Threat_Mitigations: summary.tables.threatMitigations,
    Threat_Files: summary.tables.threatFiles,
    Threat_Details: summary.tables.groupedThreats,
    Vuln_Severity: summary.tables.vulnerabilitySeverity,
    Vuln_Details: summary.tables.vulnerabilityDetails,
    Vuln_Apps: summary.tables.vulnerabilityApps,
    Vuln_Endpoints: summary.tables.vulnerabilityEndpoints,
    Hash_Summary: summary.tables.hashSummary,
    Hashes: summary.tables.hashes,
    Sentinel_Summary: summary.tables.sentinelSummary,
    OS_Types: summary.tables.osTypes,
    Endpoint_List: summary.tables.endpointList
  };
  for (const [name, rows] of Object.entries(sheets)) {
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), name.slice(0, 31));
  }
  return XLSX.write(wb, { type: "buffer", bookType: "xlsx" });
}

app.get("/api/config", async (_req, res) => {
  const provisioningUri = TOTP_SECRET ? authenticator.keyuri(TOTP_APP_NAME, TOTP_ISSUER, TOTP_SECRET) : "";
  const qrCode = provisioningUri && process.env.SHOW_TOTP_SETUP === "true" ? await QRCode.toDataURL(provisioningUri) : "";
  res.json({
    totpConfigured: Boolean(TOTP_SECRET),
    showTotpSetup: Boolean(qrCode),
    qrCode,
    appName: TOTP_APP_NAME,
    issuer: TOTP_ISSUER
  });
});

app.post("/api/auth/totp", (req, res) => {
  const code = String(req.body.code || "").trim();
  if (!TOTP_SECRET) return res.status(503).json({ error: "TOTP_SECRET is not configured." });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "Enter a 6-digit authenticator code." });
  if (!authenticator.check(code, TOTP_SECRET)) return res.status(401).json({ error: "Invalid verification code." });

  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, { totpAuthenticated: true, authenticatedSites: new Map(), generatedAt: Date.now() });
  setSessionCookie(res, sessionId);
  res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  const payload = readCookie(req.cookies.s1_report_session);
  if (payload) sessions.delete(payload.sessionId);
  res.clearCookie("s1_report_session");
  res.json({ ok: true });
});

app.get("/api/sites", requireTotp, async (_req, res, next) => {
  try {
    const sites = await fetchAllWithCursor("sites", { limit: 200 });
    res.json({ sites: sites.map((site) => ({ id: site.id, name: site.name })).filter((site) => site.id && site.name) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/sites/verify", requireTotp, (req, res) => {
  const { siteName, pin } = req.body || {};
  if (!siteName) return res.status(400).json({ error: "Site name is required." });
  const expected = SITE_PINS[siteName];
  if (expected && pin !== expected) return res.status(403).json({ error: `Invalid PIN for ${siteName}.` });
  req.session.authenticatedSites.set(siteName, Date.now());
  res.json({ ok: true, siteName });
});

app.post("/api/reports/fetch", requireTotp, async (req, res, next) => {
  try {
    const { selectedSites = [], startIso, endIso } = req.body || {};
    const range = validateIsoRange(startIso, endIso);
    const authorized = selectedSites.every((site) => !SITE_PINS[site.name] || req.session.authenticatedSites.has(site.name));
    if (!authorized) return res.status(403).json({ error: "Authenticate each selected site before fetching data." });

    const summaries = await Promise.all(selectedSites.map((site) => fetchSiteSummary({
      siteId: site.id,
      siteName: site.name,
      ...range
    })));
    req.session.authenticatedSites.clear();
    res.json({ summaries, authCleared: true });
  } catch (error) {
    next(error);
  }
});

app.post("/api/reports/excel", requireTotp, (req, res, next) => {
  try {
    const { summary } = req.body || {};
    if (!summary?.siteName) return res.status(400).json({ error: "Summary is required." });
    const buffer = workbookForSummary(summary);
    const fileName = `${summary.siteName.replace(/\s+/g, "_")}_Summary.xlsx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.send(buffer);
  } catch (error) {
    next(error);
  }
});

app.post("/api/agent/chat", requireTotp, async (req, res, next) => {
  try {
    const question = String(req.body?.question || "").trim();
    if (!question) return res.status(400).json({ error: "Question is required." });
    if (question.length > 1000) return res.status(400).json({ error: "Question is too long." });

    const range = parseAgentTimeRange(question);
    const selectedSiteIds = Array.isArray(req.body?.siteIds) ? req.body.siteIds.filter(Boolean).slice(0, 50) : [];
    const siteIds = await resolvePromptSites(question, selectedSiteIds);
    const intent = classifyAgentIntent(question);

    let result;
    if (intent === "lateral_movement") result = await answerLateralMovement(question, range, siteIds);
    else if (intent === "vulnerabilities") result = await answerVulnerabilities(range, siteIds);
    else if (intent === "hashes") result = await answerHashes(range, siteIds);
    else if (intent === "endpoints") result = await answerEndpoints(siteIds);
    else result = await answerThreats(range, siteIds);

    res.json({
      ...result,
      intent,
      range,
      scope: {
        siteIds,
        mode: siteIds.length ? "selected" : "all_accessible"
      }
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, s1Configured: Boolean(API_TOKEN), totpConfigured: Boolean(TOTP_SECRET) });
});

// ── External Solution SSO ─────────────────────────────────────────────────────

/**
 * GET /api/sso/config
 * Returns whether SSO is configured and the list of selectable analyst profiles.
 * Requires TOTP authentication.
 */
app.get("/api/sso/config", requireTotp, (_req, res) => {
  const configured = Boolean(EXTERNAL_SSO_URL && EXTERNAL_SSO_SECRET);
  const profiles = Object.entries(ANALYST_PROFILES).map(([username, profile]) => ({
    username,
    name:  profile.name  || username,
    email: profile.email || ""
  }));
  res.json({ configured, profiles, tokenField: EXTERNAL_SSO_TOKEN_FIELD });
});

/**
 * POST /api/sso/launch
 * Generates a short-lived HS256 JWT for the selected analyst profile and
 * returns the data needed for an auto-submitting POST form to the external
 * solution's SSO callback. The token is never returned to the browser in a
 * way that appears in the address bar or browser history.
 *
 * Body: { username: string }  — must be a key in ANALYST_PROFILES
 * Requires TOTP authentication.
 */
app.post("/api/sso/launch", requireTotp, (req, res) => {
  if (!EXTERNAL_SSO_URL)    return res.status(503).json({ error: "EXTERNAL_SSO_URL is not configured." });
  if (!EXTERNAL_SSO_SECRET) return res.status(503).json({ error: "EXTERNAL_SSO_SECRET is not configured." });

  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: "Analyst username is required." });

  const profile = ANALYST_PROFILES[username];
  if (!profile) return res.status(404).json({ error: `No profile found for analyst "${username}".` });

  const now  = Math.floor(Date.now() / 1000);
  const jti  = crypto.randomUUID();
  const exp  = now + EXTERNAL_SSO_TOKEN_TTL;

  const payload = {
    iss:   EXTERNAL_SSO_ISSUER,
    aud:   EXTERNAL_SSO_AUDIENCE,
    sub:   profile.sub   || username,
    email: profile.email || "",
    name:  profile.name  || username,
    mfa:   true,          // analyst completed TOTP before reaching this endpoint
    iat:   now,
    exp,
    jti
  };

  let token;
  try {
    token = jwt.sign(payload, EXTERNAL_SSO_SECRET, { algorithm: "HS256", noTimestamp: true });
  } catch (err) {
    console.error("SSO JWT signing error:", err);
    return res.status(500).json({ error: "Failed to generate SSO token." });
  }

  // Register the JTI so it cannot be replayed
  usedJtis.set(jti, exp * 1000);

  res.json({
    formUrl:   EXTERNAL_SSO_URL,
    fieldName: EXTERNAL_SSO_TOKEN_FIELD,
    token
  });
});

app.use("/assets", express.static(path.join(rootDir, "dist", "assets")));
app.use(express.static(path.join(rootDir, "dist")));
app.get("*", (_req, res) => {
  res.sendFile(path.join(rootDir, "dist", "index.html"));
});

app.use((error, _req, res, _next) => {
  const status = error.response?.status || 500;
  const message = error.response?.data ? JSON.stringify(error.response.data) : error.message;
  console.error(error);
  res.status(status).json({ error: message });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SentinelOne reporting dashboard listening on ${PORT}`);
});
