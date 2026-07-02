import React, { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bot,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Clock,
  Database,
  ExternalLink,
  Loader2,
  Lock,
  LogOut,
  MessageSquare,
  Search,
  Send,
  Shield,
  Sparkles,
  TerminalSquare,
  User,
  XCircle
} from "lucide-react";

const EXAMPLE_PROMPTS = [
  "How many lateral movements occurred within this week?",
  "Show unresolved high severity threats this month",
  "Which endpoints had the most threats in the last 7 days?",
  "Summarize vulnerabilities by severity for RoutePay",
  "How many blocklisted hashes were added this week?"
];

const ICONS = {
  Activity,
  AlertTriangle,
  Database,
  Search,
  Shield
};

const initialMessages = [
  {
    id: "welcome",
    role: "assistant",
    content:
      "Ask about SentinelOne activity, endpoints, threats, vulnerabilities, hashes, or lateral movement. I will query the tenant and show the evidence I used.",
    meta: {
      label: "SOC Agent",
      confidence: "Ready"
    }
  }
];

function cx(...parts) {
  return parts.filter(Boolean).join(" ");
}

function formatDate(value) {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function Metric({ label, value, tone = "neutral", icon: Icon = Activity }) {
  const MetricIcon = typeof Icon === "string" ? ICONS[Icon] || Activity : Icon;
  return (
    <div className={cx("metric", `metric-${tone}`)}>
      <div className="metric-icon">
        <MetricIcon size={16} />
      </div>
      <div>
        <div className="metric-value">{value}</div>
        <div className="metric-label">{label}</div>
      </div>
    </div>
  );
}

function LoginPanel({ config, onLogin }) {
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      await axios.post("/api/auth/totp", { code });
      onLogin();
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-card">
        <div className="brand-mark">
          <Shield size={28} />
        </div>
        <div>
          <p className="eyebrow">SentinelOne Agentic SOC</p>
          <h1>Analyst Console</h1>
          <p className="login-copy">Sign in to query tenant telemetry through the SOC agent.</p>
        </div>
        {config?.showTotpSetup && config.qrCode ? (
          <img className="qr-code" src={config.qrCode} alt="Authenticator QR code" />
        ) : null}
        <form onSubmit={submit} className="login-form">
          <label htmlFor="totp">Authenticator code</label>
          <div className="code-row">
            <Lock size={18} />
            <input
              id="totp"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))}
              placeholder="000000"
              autoFocus
            />
          </div>
          {error ? <div className="error-line">{error}</div> : null}
          <button type="submit" className="primary-button" disabled={loading || code.length !== 6}>
            {loading ? <Loader2 className="spin" size={18} /> : <CheckCircle2 size={18} />}
            Verify
          </button>
        </form>
      </section>
    </main>
  );
}

// ── External Platform SSO Panel ───────────────────────────────────────────────
function ExternalPanel({ ssoConfig }) {
  const [selectedUsername, setSelectedUsername] = useState("");
  const [launching, setLaunching]               = useState(false);
  const [error, setError]                       = useState("");
  const [launched, setLaunched]                 = useState(false);

  const profiles = ssoConfig?.profiles || [];

  // Auto-select if only one profile exists
  useEffect(() => {
    if (profiles.length === 1 && !selectedUsername) {
      setSelectedUsername(profiles[0].username);
    }
  }, [profiles]);

  async function handleLaunch() {
    if (!selectedUsername || launching) return;
    setError("");
    setLaunching(true);
    try {
      const { data } = await axios.post("/api/sso/launch", { username: selectedUsername });
      // Build a hidden auto-submitting POST form and open in new tab.
      // This keeps the token out of the browser address bar / history.
      const form = document.createElement("form");
      form.method = "POST";
      form.action = data.formUrl;
      form.target = "_blank";
      form.rel    = "noopener noreferrer";

      const input = document.createElement("input");
      input.type  = "hidden";
      input.name  = data.fieldName;
      input.value = data.token;
      form.appendChild(input);

      document.body.appendChild(form);
      form.submit();
      document.body.removeChild(form);

      setLaunched(true);
      setTimeout(() => setLaunched(false), 4000);
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Launch failed. Please try again.");
    } finally {
      setLaunching(false);
    }
  }

  if (!ssoConfig?.configured) {
    return (
      <div className="external-panel">
        <div className="external-unconfigured">
          <div className="ext-icon-wrap unconfigured">
            <ExternalLink size={28} />
          </div>
          <h2>External Platform</h2>
          <p>The external solution SSO is not yet configured. Add <code>EXTERNAL_SSO_URL</code> and <code>EXTERNAL_SSO_SECRET</code> to your <code>.env</code> file and restart the server.</p>
        </div>
      </div>
    );
  }

  const selectedProfile = profiles.find((p) => p.username === selectedUsername);

  return (
    <div className="external-panel">
      <div className="external-launch-card">
        <div className="ext-icon-wrap">
          <ExternalLink size={28} />
        </div>

        <div className="ext-header">
          <p className="eyebrow">Integrated Solution</p>
          <h2>External Platform</h2>
          <p className="ext-desc">
            Launch the external platform in a new tab. A short-lived, signed token will be
            generated server-side and used to authenticate you automatically — no second login required.
          </p>
        </div>

        <div className="ext-form">
          {profiles.length > 1 && (
            <div className="ext-field">
              <label htmlFor="analyst-select">Select your analyst profile</label>
              <div className="ext-select-wrap">
                <select
                  id="analyst-select"
                  value={selectedUsername}
                  onChange={(e) => { setSelectedUsername(e.target.value); setError(""); }}
                >
                  <option value="">— choose profile —</option>
                  {profiles.map((p) => (
                    <option key={p.username} value={p.username}>
                      {p.name} ({p.email})
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}

          {selectedProfile && (
            <div className="ext-identity-card">
              <div className="ext-avatar">
                <User size={18} />
              </div>
              <div>
                <strong>{selectedProfile.name}</strong>
                <span>{selectedProfile.email}</span>
              </div>
            </div>
          )}

          {error && <div className="error-line ext-error">{error}</div>}

          {launched && (
            <div className="ext-success">
              <CheckCircle2 size={16} />
              Opened in a new tab — you are now authenticated.
            </div>
          )}

          <button
            id="sso-launch-btn"
            type="button"
            className="launch-button"
            disabled={!selectedUsername || launching}
            onClick={handleLaunch}
          >
            {launching
              ? <><Loader2 className="spin" size={18} /> Generating token&hellip;</>
              : <><ExternalLink size={18} /> Launch External Platform <ChevronRight size={16} /></>}
          </button>
        </div>

        <div className="ext-security-note">
          <Lock size={13} />
          Token is generated server-side, expires in 60 seconds, and is protected against replay attacks.
        </div>
      </div>
    </div>
  );
}

function EvidencePanel({ message }) {
  const evidence = message.evidence || [];
  const plan = message.plan || [];

  return (
    <aside className="evidence-panel">
      <div className="panel-header">
        <span>Evidence</span>
        <Database size={16} />
      </div>
      {message.metrics?.length ? (
        <div className="metric-grid">
          {message.metrics.map((metric) => (
            <Metric key={metric.label} {...metric} />
          ))}
        </div>
      ) : (
        <div className="empty-state">Run a query to populate evidence.</div>
      )}

      <div className="panel-section">
        <div className="section-title">Query Plan</div>
        {plan.length ? (
          <ol className="plan-list">
            {plan.map((step, index) => (
              <li key={`${step}-${index}`}>{step}</li>
            ))}
          </ol>
        ) : (
          <div className="empty-state compact">No plan yet.</div>
        )}
      </div>

      <div className="panel-section">
        <div className="section-title">Sample Rows</div>
        {evidence.length ? (
          <div className="evidence-list">
            {evidence.map((item, index) => (
              <div className="evidence-item" key={`${item.id || item.name || index}`}>
                <div className="evidence-main">
                  <span>{item.title || item.name || "SentinelOne record"}</span>
                  <small>{item.subtitle || item.type || "Telemetry"}</small>
                </div>
                <span className="evidence-time">{formatDate(item.time)}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state compact">No rows selected.</div>
        )}
      </div>
    </aside>
  );
}

function MessageBubble({ message }) {
  const isUser = message.role === "user";
  return (
    <article className={cx("message", isUser ? "message-user" : "message-agent")}>
      <div className="message-avatar">{isUser ? <User size={16} /> : <Bot size={16} />}</div>
      <div className="message-body">
        <div className="message-meta">
          <span>{isUser ? "You" : message.meta?.label || "SOC Agent"}</span>
          {message.meta?.confidence ? <span>{message.meta.confidence}</span> : null}
        </div>
        <p>{message.content}</p>
        {message.findings?.length ? (
          <div className="finding-list">
            {message.findings.map((finding, index) => (
              <div className="finding" key={`${finding.label}-${index}`}>
                <strong>{finding.value}</strong>
                <span>{finding.label}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </article>
  );
}

function App() {
  const [config, setConfig]               = useState(null);
  const [health, setHealth]               = useState(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking]           = useState(true);
  const [sites, setSites]                 = useState([]);
  const [selectedSiteIds, setSelectedSiteIds] = useState([]);
  const [messages, setMessages]           = useState(initialMessages);
  const [input, setInput]                 = useState("");
  const [loading, setLoading]             = useState(false);
  const [error, setError]                 = useState("");
  const [activeTab, setActiveTab]         = useState("chat");   // "chat" | "external"
  const [ssoConfig, setSsoConfig]         = useState(null);
  const endRef = useRef(null);

  const latestAgentMessage = useMemo(
    () => [...messages].reverse().find((message) => message.role === "assistant" && message.id !== "welcome") || messages[0],
    [messages]
  );

  useEffect(() => {
    async function bootstrap() {
      try {
        const [configResponse, healthResponse] = await Promise.all([
          axios.get("/api/config"),
          axios.get("/api/health")
        ]);
        setConfig(configResponse.data);
        setHealth(healthResponse.data);
        if (!configResponse.data.totpConfigured) {
          setAuthenticated(true);
        }
      } catch (err) {
        setError(err.response?.data?.error || err.message);
      } finally {
        setChecking(false);
      }
    }
    bootstrap();
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    async function loadSites() {
      try {
        const response = await axios.get("/api/sites");
        setSites(response.data.sites || []);
      } catch (err) {
        if (err.response?.status === 401) setAuthenticated(false);
        else setError(err.response?.data?.error || err.message);
      }
    }
    async function loadSsoConfig() {
      try {
        const response = await axios.get("/api/sso/config");
        setSsoConfig(response.data);
      } catch {
        setSsoConfig({ configured: false, profiles: [] });
      }
    }
    loadSites();
    loadSsoConfig();
  }, [authenticated]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  async function refreshAfterLogin() {
    setAuthenticated(true);
    setError("");
  }

  async function logout() {
    await axios.post("/api/auth/logout");
    setAuthenticated(false);
    setSites([]);
    setSelectedSiteIds([]);
    setMessages(initialMessages);
    setSsoConfig(null);
    setActiveTab("chat");
  }

  function toggleSite(siteId) {
    setSelectedSiteIds((current) =>
      current.includes(siteId) ? current.filter((id) => id !== siteId) : [...current, siteId]
    );
  }

  async function askAgent(prompt = input) {
    const question = prompt.trim();
    if (!question || loading) return;
    setInput("");
    setError("");
    const userMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: question
    };
    setMessages((current) => [...current, userMessage]);
    setLoading(true);
    try {
      const response = await axios.post("/api/agent/chat", {
        question,
        siteIds: selectedSiteIds
      });
      const answer = response.data;
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content: answer.answer,
          findings: answer.findings,
          evidence: answer.evidence,
          metrics: answer.metrics,
          plan: answer.plan,
          meta: {
            label: answer.agent || "SOC Agent",
            confidence: answer.confidence || "Evidence-backed"
          }
        }
      ]);
    } catch (err) {
      const message = err.response?.data?.error || err.message || "The agent could not complete the query.";
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content: message,
          meta: { label: "SOC Agent", confidence: "Error" }
        }
      ]);
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <main className="loading-shell">
        <Loader2 className="spin" size={28} />
      </main>
    );
  }

  if (!authenticated && config?.totpConfigured) {
    return <LoginPanel config={config} onLogin={refreshAfterLogin} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark small">
            <Shield size={22} />
          </div>
          <div>
            <strong>Sentrium SOC</strong>
            <span>SentinelOne</span>
          </div>
        </div>

        <div className="status-stack">
          <div className={cx("status-pill", health?.s1Configured ? "good" : "bad")}>
            {health?.s1Configured ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
            API
          </div>
          <div className={cx("status-pill", health?.totpConfigured ? "good" : "warn")}>
            <Lock size={15} />
            TOTP
          </div>
          {ssoConfig?.configured && (
            <div className="status-pill good">
              <ExternalLink size={13} />
              SSO
            </div>
          )}
        </div>

        {/* ── Navigation Tabs ── */}
        <div className="nav-tabs">
          <button
            id="tab-chat"
            type="button"
            className={cx("nav-tab", activeTab === "chat" && "active")}
            onClick={() => setActiveTab("chat")}
          >
            <MessageSquare size={15} />
            SOC AI Chat
          </button>
          <button
            id="tab-external"
            type="button"
            className={cx("nav-tab", activeTab === "external" && "active")}
            onClick={() => setActiveTab("external")}
          >
            <ExternalLink size={15} />
            External Platform
          </button>
        </div>

        {/* Scope selector — only relevant for chat tab */}
        {activeTab === "chat" && (
          <>
            <div className="site-toolbar">
              <div>
                <span className="section-title">Scope</span>
                <small>{selectedSiteIds.length ? `${selectedSiteIds.length} selected` : "All accessible sites"}</small>
              </div>
              <button type="button" onClick={() => setSelectedSiteIds([])} className="ghost-button">
                Clear
              </button>
            </div>

            <div className="site-list">
              {sites.length ? (
                sites.map((site) => (
                  <button
                    key={site.id}
                    type="button"
                    onClick={() => toggleSite(site.id)}
                    className={cx("site-item", selectedSiteIds.includes(site.id) && "selected")}
                  >
                    <span>{site.name}</span>
                    {selectedSiteIds.includes(site.id) ? <CheckCircle2 size={15} /> : null}
                  </button>
                ))
              ) : (
                <div className="empty-state compact">No sites loaded.</div>
              )}
            </div>
          </>
        )}

        {/* Spacer pushes logout to bottom when external tab hides site list */}
        {activeTab === "external" && <div style={{ flex: 1 }} />}

        <button type="button" className="logout-button" onClick={logout}>
          <LogOut size={16} />
          Sign out
        </button>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Agentic SOC Console</p>
            <h1>{activeTab === "chat" ? "SentinelOne Intelligence Chat" : "External Platform"}</h1>
          </div>
          <div className="topbar-actions">
            <Metric label="Sites" value={sites.length || "0"} icon={Database} />
            <Metric label="Scope" value={selectedSiteIds.length || "All"} icon={Search} tone="accent" />
          </div>
        </header>

        {error ? <div className="notice error-line">{error}</div> : null}

        {activeTab === "chat" ? (
          <>
            <section className="agent-grid">
              <div className="chat-panel">
                <div className="prompt-strip">
                  {EXAMPLE_PROMPTS.map((prompt) => (
                    <button key={prompt} type="button" onClick={() => askAgent(prompt)}>
                      <Sparkles size={14} />
                      {prompt}
                    </button>
                  ))}
                </div>

                <div className="messages">
                  {messages.map((message) => (
                    <MessageBubble key={message.id} message={message} />
                  ))}
                  {loading ? (
                    <article className="message message-agent">
                      <div className="message-avatar">
                        <Bot size={16} />
                      </div>
                      <div className="message-body">
                        <div className="message-meta">
                          <span>SOC Agent</span>
                          <span>Querying SentinelOne</span>
                        </div>
                        <p className="typing-row">
                          <Loader2 className="spin" size={16} />
                          Running read-only tools and preparing evidence.
                        </p>
                      </div>
                    </article>
                  ) : null}
                  <div ref={endRef} />
                </div>

                <form
                  className="composer"
                  onSubmit={(event) => {
                    event.preventDefault();
                    askAgent();
                  }}
                >
                  <TerminalSquare size={20} />
                  <input
                    value={input}
                    onChange={(event) => setInput(event.target.value)}
                    placeholder="Ask a SentinelOne question..."
                  />
                  <button type="submit" disabled={loading || !input.trim()} title="Send">
                    {loading ? <Loader2 className="spin" size={18} /> : <Send size={18} />}
                  </button>
                </form>
              </div>

              <EvidencePanel message={latestAgentMessage} />
            </section>

            <section className="workflow-band">
              <div>
                <Clock size={18} />
                <span>Triage</span>
              </div>
              <ArrowUpRight size={16} />
              <div>
                <Search size={18} />
                <span>Investigate</span>
              </div>
              <ArrowUpRight size={16} />
              <div>
                <CalendarDays size={18} />
                <span>Correlate</span>
              </div>
              <ArrowUpRight size={16} />
              <div>
                <AlertTriangle size={18} />
                <span>Escalate</span>
              </div>
            </section>
          </>
        ) : (
          <ExternalPanel ssoConfig={ssoConfig} />
        )}
      </main>
    </div>
  );
}

export default App;
