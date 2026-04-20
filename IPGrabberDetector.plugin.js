/**
 * @name IPGrabberDetector
 * @description Detects IP grabbers, trackers, and suspicious links in messages. Highlights flagged messages and warns you before your IP is exposed.
 * @version 3.0.0
 * @author y4ron1
 * @authorLink https://github.com/0neBeerLeft/
 * @source https://github.com/YourName/IPGrabberDetector
 */

const REMOTE_DB_URL = "https://raw.githubusercontent.com/0neBeerLeft/IPGrabberDetector/refs/heads/main/domains.json";

const GRABBER_PATTERNS = [
    { pattern: /grabify\.(?:link|org|cc|gg)\/[a-zA-Z0-9]+/i,           level: "danger",  reason: "Grabify IP-grabber link" },
    { pattern: /iplogger\.(?:org|com|ru|co|info)\/\w+/i,                level: "danger",  reason: "IPLogger tracking link" },
    { pattern: /[?&](track(?:er|ing)?|log(?:ger)?|grabip|iptrack|visitor)=[^&\s]+/i, level: "warning", reason: "URL contains tracking query parameter" },
    { pattern: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?(?:\/|$)/, level: "danger", reason: "URL points directly to a raw IP address" },
];

const THREAT_PRIORITY = { danger: 3, warning: 2, info: 1 };
const STYLE_ID = "ipgrabber-detector-styles";

let DOMAIN_MAP = new Map();

const CSS = `
[data-ipgrab] {
    border-radius: 4px !important;
    position: relative !important;
    transition: background-color 0.2s ease !important;
}
[data-ipgrab="danger"]  { background-color: rgba(237,66,69,0.10) !important; box-shadow: inset 3px 0 0 #ed4245 !important; }
[data-ipgrab="warning"] { background-color: rgba(250,168,26,0.08) !important; box-shadow: inset 3px 0 0 #faa81a !important; }
[data-ipgrab="info"]    { background-color: rgba(88,101,242,0.07) !important; box-shadow: inset 3px 0 0 #5865f2 !important; }

/* Color every anchor/link-role element inside a flagged message */
[data-ipgrab="danger"]  a,
[data-ipgrab="danger"]  [role="link"],
[data-ipgrab="danger"]  [class*="anchor"],
[data-ipgrab="danger"]  [class*="link"] {
    color: #ed4245 !important;
    text-decoration: underline wavy #ed4245 !important;
}
[data-ipgrab="warning"] a,
[data-ipgrab="warning"] [role="link"],
[data-ipgrab="warning"] [class*="anchor"],
[data-ipgrab="warning"] [class*="link"] {
    color: #faa81a !important;
    text-decoration: underline wavy #faa81a !important;
}
[data-ipgrab="info"] a,
[data-ipgrab="info"] [role="link"],
[data-ipgrab="info"] [class*="anchor"],
[data-ipgrab="info"] [class*="link"] {
    color: #7289da !important;
    text-decoration: underline dotted #7289da !important;
}
`;


function extractUrls(text) {
    if (!text) return [];
    const matches = text.match(/\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{2,5})?(?:\/[\w\-._~%!$&'()*+,;=:@\/?#\[\]]*)?/gi) ?? [];
    const cleaned = matches
        .map(u => u.replace(/[),.;!?]+$/g, ""))
        .filter(Boolean);
    return Array.from(new Set(cleaned));
}

function normalizeRemoteDbUrl(url) {
    try {
        const u = new URL(url);
        if (u.hostname !== "github.com") return url;
        const parts = u.pathname.split("/").filter(Boolean);
        if (parts.length >= 5 && parts[2] === "blob") {
            const [owner, repo, , ...rest] = parts;
            const rawPath = rest.join("/");
            return `https://raw.githubusercontent.com/${owner}/${repo}/${rawPath}`;
        }
    } catch {
    }
    return url;
}

function analyzeUrl(rawUrl) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch {
        try {
            parsed = new URL(`https://${rawUrl}`);
        } catch {
            for (const { pattern, reason, level } of GRABBER_PATTERNS) {
                if (pattern.test(rawUrl)) return { url: rawUrl, reason, level };
            }
            return null;
        }
    }

    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");

    const exact = DOMAIN_MAP.get(hostname);
    if (exact) return { url: rawUrl, reason: exact.reason, level: exact.level, matched: exact.domain };

    for (const [domain, entry] of DOMAIN_MAP) {
        if (hostname.endsWith(`.${domain}`))
            return { url: rawUrl, reason: `${entry.reason} (subdomain of ${domain})`, level: entry.level, matched: domain };
    }

    for (const { pattern, reason, level } of GRABBER_PATTERNS) {
        if (pattern.test(rawUrl)) return { url: rawUrl, reason, level };
    }

    return null;
}

function worstLevel(threats) {
    return threats.reduce((w, t) => THREAT_PRIORITY[t.level] > THREAT_PRIORITY[w] ? t.level : w, "info");
}

function makeShortLabel(threats) {
    if (!Array.isArray(threats) || threats.length === 0) return "";
    const worst = worstLevel(threats);
    const top = threats.find(t => t.level === worst) ?? threats[0];
    const prefix = worst === "danger" ? "⚠" : worst === "warning" ? "⚠" : "ℹ";
    const reason = (top?.reason ?? "Flagged link").trim();
    const max = 26;
    const short = reason.length > max ? reason.slice(0, max - 1) + "…" : reason;
    return `${prefix} ${short}`;
}

function makeTooltip(threats) {
    if (!Array.isArray(threats) || threats.length === 0) return "";
    const lines = threats.map(t => {
        const url = (t.url ?? "").trim();
        const reason = (t.reason ?? "").trim();
        return url ? `${reason}\n${url}` : reason;
    }).filter(Boolean);
    return lines.join("\n\n");
}

function makeSnowflake(now = Date.now()) {
    const discordEpoch = 1420070400000n;
    const ts = BigInt(now);
    const timePart = (ts - discordEpoch) << 22n;
    return (timePart).toString();
}

function buildWarningEmbed(threats, edited = false) {
    const worst = worstLevel(threats);
    const icons   = { danger: "🔴", warning: "🟡", info: "🔵" };
    const colors  = { danger: 0xed4245, warning: 0xfaa81a, info: 0x5865f2 };
    const titles  = { danger: "🚨 IP Grabber Detected", warning: "⚠️ Suspicious Link", info: "ℹ️ Tracked Link" };
    const footers = {
        danger:  "Do NOT click these links. They may expose your IP address and location to the sender.",
        warning: "Be cautious before clicking. These links may hide their destination or track your IP.",
        info:    "These links were flagged for informational purposes only.",
    };

    const description = [
        edited ? "*This is a re-check after the message was edited.*\n" : "",
        threats.map(t => {
            const url = t.url.length > 80 ? t.url.slice(0, 77) + "…" : t.url;
            return `${icons[t.level]} **${t.reason}**\n\`${url}\``;
        }).join("\n\n"),
    ].filter(Boolean).join("\n");

    return {
        type: "rich",
        color: colors[worst],
        title: `${titles[worst]} — ${threats.length} flagged link${threats.length > 1 ? "s" : ""}`,
        description,
        footer: { text: footers[worst] },
    };
}


module.exports = class IPGrabberDetector {
    constructor(meta) {
        this.meta = meta;
        this._onMessage       = this._onMessage.bind(this);
        this._onMessageUpdate = this._onMessageUpdate.bind(this);
        this._onMessageDelete = this._onMessageDelete.bind(this);
        this._onChannelSelect = this._onChannelSelect.bind(this);
        this._highlighted     = new Set();
        this._mutationObserver = null;
        this._messageStore = null;
        this._selectedChannelStore = null;
        this._debugLastToastAt = 0;
        this._receiveMessageMod = null;
        this._incomingDispatchMod = null;
        this._rescanTimer = null;
    }

    _debugToast(text, type = "info") {
        const cfg = this._config();
        if (!cfg.debugToasts) return;
        const now = Date.now();
        if (now - this._debugLastToastAt < 1200) return;
        this._debugLastToastAt = now;
        BdApi.UI.showToast(text, { type, timeout: 2500 });
    }


    start() {
        this._injectStyles();
        this._fetchRemoteDb();
        this._startMutationObserver();

        BdApi.UI.showToast("IPGrabberDetector enabled", { type: "success" });

        console.log("[IPGrabberDetector] start()");
        this._debugToast("IPGrabberDetector: started", "success");

        const byProps = BdApi.Webpack?.Filters?.byProps;
        const dispatcherFilter = byProps ? byProps("dispatch", "subscribe") : (m => m?.dispatch && m?.subscribe);
        this._dispatcher = BdApi.Webpack.getModule(dispatcherFilter, { searchExports: false })
            ?? BdApi.Webpack.getModule(dispatcherFilter, { searchExports: true });
        this._messageStore = BdApi.Webpack.getModule(m => m?.getMessages && m?.getMessage, { searchExports: false });
        this._selectedChannelStore = BdApi.Webpack.getModule(m => m?.getChannelId && typeof m.getChannelId === "function", { searchExports: false });
        if (this._dispatcher) {
            this._dispatcher.subscribe("MESSAGE_CREATE", this._onMessage);
            this._dispatcher.subscribe("MESSAGE_UPDATE", this._onMessageUpdate);
            this._dispatcher.subscribe("MESSAGE_DELETE", this._onMessageDelete);
            this._dispatcher.subscribe("CHANNEL_SELECT", this._onChannelSelect);
            this._dispatcher.subscribe("LOAD_MESSAGES_SUCCESS", this._onChannelSelect);

            if (typeof this._dispatcher.dispatch === "function") {
                BdApi.Patcher.after(this.meta.name, this._dispatcher, "dispatch", (_this, args) => {
                    try {
                        const action = args?.[0];
                        const type = action?.type;
                        if (!type) return;

                        if (type === "MESSAGE_CREATE") {
                            const msg = action?.message ?? action?.messageRecord;
                            if (msg?.id) this._handle(msg, false);
                        } else if (type === "MESSAGE_UPDATE") {
                            if (!this._config().warnOnEdit) return;
                            const msg = action?.message ?? action?.messageRecord;
                            if (msg?.id) this._handle(msg, true);
                        } else if (type === "CHANNEL_SELECT" || type === "LOAD_MESSAGES_SUCCESS") {
                            this._scanCurrentChannel();
                            this._scanDomForLinks();
                        }
                    } catch {
                    }
                });
            }
        } else {
            BdApi.UI.showToast("IPGrabberDetector: could not hook dispatcher", { type: "error" });
            console.warn("[IPGrabberDetector] Dispatcher hook failed");
            this._debugToast("IPGrabberDetector: dispatcher hook failed", "error");
        }

        this._scanCurrentChannel();
        this._scanDomForLinks();

        try {
            this._receiveMessageMod = BdApi.Webpack.getModule(m => typeof m?.receiveMessage === "function", { searchExports: false });
            if (this._receiveMessageMod?.receiveMessage) {
                BdApi.Patcher.after(this.meta.name, this._receiveMessageMod, "receiveMessage", (_this, args) => {
                    try {
                        const channelId = args?.[0];
                        const msg = args?.[1];
                        if (!msg?.id) return;
                        this._debugToast(`IPGrabberDetector: recv ${msg.id}`, "info");
                        this._handle(msg, false);
                    } catch {
                    }
                });
                this._debugToast("IPGrabberDetector: receiveMessage hook active", "success");
            } else {
                this._debugToast("IPGrabberDetector: receiveMessage hook not found", "error");
            }
        } catch {
            this._debugToast("IPGrabberDetector: receiveMessage hook failed", "error");
        }

        try {
            this._incomingDispatchMod = BdApi.Webpack.getModule(m => typeof m?.dispatch_MESSAGE_CREATE === "function", { searchExports: false });
            if (this._incomingDispatchMod?.dispatch_MESSAGE_CREATE) {
                BdApi.Patcher.after(this.meta.name, this._incomingDispatchMod, "dispatch_MESSAGE_CREATE", (_this, args) => {
                    try {
                        const payload = args?.[0];
                        const msg = payload?.message ?? payload?.messageRecord ?? payload;
                        if (!msg?.id) return;
                        this._handle(msg, false);
                    } catch {
                    }
                });
            }
            if (this._incomingDispatchMod?.dispatch_MESSAGE_UPDATE) {
                BdApi.Patcher.after(this.meta.name, this._incomingDispatchMod, "dispatch_MESSAGE_UPDATE", (_this, args) => {
                    try {
                        const payload = args?.[0];
                        const msg = payload?.message ?? payload?.messageRecord ?? payload;
                        if (!msg?.id) return;
                        if (!this._config().warnOnEdit) return;
                        this._handle(msg, true);
                    } catch {
                    }
                });
            }
        } catch {
        }
    }

    stop() {
        if (this._dispatcher) {
            this._dispatcher.unsubscribe("MESSAGE_CREATE", this._onMessage);
            this._dispatcher.unsubscribe("MESSAGE_UPDATE", this._onMessageUpdate);
            this._dispatcher.unsubscribe("MESSAGE_DELETE", this._onMessageDelete);
            this._dispatcher.unsubscribe("CHANNEL_SELECT", this._onChannelSelect);
            this._dispatcher.unsubscribe("LOAD_MESSAGES_SUCCESS", this._onChannelSelect);
        }
        if (this._mutationObserver) {
            this._mutationObserver.disconnect();
            this._mutationObserver = null;
        }
        if (this._rescanTimer) {
            clearTimeout(this._rescanTimer);
            this._rescanTimer = null;
        }
        BdApi.Patcher.unpatchAll(this.meta.name);
        this._receiveMessageMod = null;
        this._incomingDispatchMod = null;
        this._removeStyles();
        document.querySelectorAll("[data-ipgrab]").forEach(el => {
            el.removeAttribute("data-ipgrab");
            el.removeAttribute("data-ipgrab-label");
        });
        this._highlighted.clear();
        BdApi.UI.showToast("IPGrabberDetector disabled", { type: "info" });
    }


    async _fetchRemoteDb() {
        try {
            const url = normalizeRemoteDbUrl(REMOTE_DB_URL);
            const res = await fetch(url, { cache: "no-cache" });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const remote = await res.json();
            if (!Array.isArray(remote)) throw new Error("Expected a JSON array");

            const next = new Map();
            let added = 0;
            for (const entry of remote) {
                const domain = entry?.domain?.toLowerCase?.();
                const level = entry?.level;
                const reason = entry?.reason;
                if (!domain || !level || !reason) continue;
                if (!THREAT_PRIORITY[level]) continue;
                next.set(domain, { domain, level, reason });
                added++;
            }

            DOMAIN_MAP = next;
            console.log(`[IPGrabberDetector] Remote DB loaded: ${added} entries.`);
            BdApi.UI.showToast(`IPGrabberDetector: Remote DB loaded (${added} entries)`, { type: "success", timeout: 4000 });

            this._scanCurrentChannel();
        } catch (err) {
            console.warn("[IPGrabberDetector] Could not load remote DB.", err);
            BdApi.UI.showToast(
                "IPGrabberDetector: Remote DB unavailable (domain list disabled). Set REMOTE_DB_URL to a raw JSON array.",
                { type: "warning", timeout: 7000 }
            );
        }
    }


    _startMutationObserver() {
        this._mutationObserver = new MutationObserver(mutations => {
            for (const { addedNodes } of mutations) {
                for (const node of addedNodes) {
                    if (node.nodeType !== 1) continue;
                    const flagged = node.closest?.("[data-ipgrab]");
                    if (!flagged) continue;
                    this._recolorLinks(flagged);
                }
            }

            if (this._rescanTimer) clearTimeout(this._rescanTimer);
            this._rescanTimer = setTimeout(() => {
                this._scanCurrentChannel();
                this._scanDomForLinks();
            }, 400);
        });
        this._mutationObserver.observe(document.body, { childList: true, subtree: true });
    }

    _recolorLinks(el) {
        const level  = el.getAttribute("data-ipgrab");
        const colors = { danger: "#ed4245", warning: "#faa81a", info: "#7289da" };
        const color  = colors[level];
        if (!color) return;

        el.querySelectorAll('a, [role="link"], [class*="anchor"], [class*="link"]').forEach(link => {
            link.style.setProperty("color", color, "important");
            link.style.setProperty("text-decoration", level === "info" ? "underline dotted" : "underline wavy", "important");
            link.style.setProperty("text-decoration-color", color, "important");
        });
    }


    getSettingsPanel() {
        const defaults = {
            warnOnDanger:  true,
            warnOnWarning: true,
            warnOnInfo:    false,
            ignoreBots:    true,
            highlight:     true,
            warnOnEdit:    true,
            debugToasts:   false,
            debugEmbeds:   false,
        };
        const saved = BdApi.Data.load(this.meta.name, "settings") ?? {};
        const cfg   = { ...defaults, ...saved };
        const save  = () => BdApi.Data.save(this.meta.name, "settings", cfg);

        const panel = document.createElement("div");
        panel.style.cssText = "padding:12px;display:flex;flex-direction:column;gap:10px;";

        const statusRow = document.createElement("div");
        statusRow.style.cssText = "padding:8px;background:rgba(88,101,242,0.1);border-radius:6px;color:var(--text-muted,#a3a6aa);font-size:12px;";
        statusRow.textContent = `Domain list: ${DOMAIN_MAP.size} entries loaded  •  Remote source: ${REMOTE_DB_URL}`;
        panel.appendChild(statusRow);

        const reloadBtn = document.createElement("button");
        reloadBtn.textContent = "🔄 Reload Remote Domain List";
        reloadBtn.style.cssText = "padding:6px 12px;background:#5865f2;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:13px;";
        reloadBtn.addEventListener("click", async () => {
            reloadBtn.disabled = true;
            reloadBtn.textContent = "Loading…";
            await this._fetchRemoteDb();
            reloadBtn.textContent = `✅ Done — ${DOMAIN_MAP.size} entries`;
            statusRow.textContent = `Domain list: ${DOMAIN_MAP.size} entries loaded  •  Remote source: ${REMOTE_DB_URL}`;
            setTimeout(() => { reloadBtn.disabled = false; reloadBtn.textContent = "🔄 Reload Remote Domain List"; }, 3000);
        });
        panel.appendChild(reloadBtn);

        const options = [
            ["warnOnDanger",  "Warn on DANGER links (IP grabbers)"],
            ["warnOnWarning", "Warn on WARNING links (shorteners, suspicious)"],
            ["warnOnInfo",    "Warn on INFO links (stat trackers etc.)"],
            ["ignoreBots",    "Ignore messages from bots"],
            ["highlight",     "Highlight flagged messages in chat"],
            ["warnOnEdit",    "Re-check messages when edited"],
            ["debugToasts",   "Debug: show toasts (helps diagnose if plugin is running)"],
            ["debugEmbeds",   "Debug: always send warning embed when threats detected"],
        ];

        for (const [key, label] of options) {
            const row = document.createElement("div");
            row.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.06);";

            const lbl = document.createElement("span");
            lbl.textContent = label;
            lbl.style.cssText = "color:var(--text-normal,#dcddde);font-size:14px;";

            const toggle = document.createElement("input");
            toggle.type    = "checkbox";
            toggle.checked = cfg[key];
            toggle.style.cssText = "width:18px;height:18px;cursor:pointer;accent-color:#5865f2;";
            toggle.addEventListener("change", () => { cfg[key] = toggle.checked; save(); });

            row.appendChild(lbl);
            row.appendChild(toggle);
            panel.appendChild(row);
        }

        return panel;
    }


    _config() {
        const defaults = {
            warnOnDanger:  true,
            warnOnWarning: true,
            warnOnInfo:    false,
            ignoreBots:    true,
            highlight:     true,
            warnOnEdit:    true,
            debugToasts:   false,
            debugEmbeds:   false,
        };
        return { ...defaults, ...(BdApi.Data.load(this.meta.name, "settings") ?? {}) };
    }


    _onMessage({ message }) {
        const msg = message ?? arguments?.[0]?.message ?? arguments?.[0]?.messageRecord ?? arguments?.[0];
        if (!msg?.id) return;
        console.log("[IPGrabberDetector] MESSAGE_CREATE", msg.id);
        this._debugToast(`IPGrabberDetector: message ${msg.id}`, "info");
        this._handle(msg, false);
    }

    _onMessageUpdate({ message }) {
        if (!this._config().warnOnEdit) return;
        const msg = message ?? arguments?.[0]?.message ?? arguments?.[0]?.messageRecord ?? arguments?.[0];
        if (!msg?.id) return;
        console.log("[IPGrabberDetector] MESSAGE_UPDATE", msg.id);
        this._debugToast(`IPGrabberDetector: update ${msg.id}`, "info");
        this._handle(msg, true);
    }

    _onMessageDelete({ message }) {
        const msg = message ?? arguments?.[0]?.message ?? arguments?.[0]?.messageRecord ?? arguments?.[0];
        if (msg?.id) {
            console.log("[IPGrabberDetector] MESSAGE_DELETE", msg.id);
            this._clearHighlight(msg.id);
        }
    }

    _onChannelSelect() {
        this._scanCurrentChannel();
        this._scanDomForLinks();
    }

    _getCurrentChannelId() {
        try {
            return this._selectedChannelStore?.getChannelId?.() ?? null;
        } catch {
            return null;
        }
    }

    _scanCurrentChannel() {
        const channelId = this._getCurrentChannelId();
        if (!channelId) return;
        this._scanChannel(channelId);
    }

    _scanDomForLinks() {
        const root =
            document.querySelector('[data-list-id="chat-messages"]') ??
            document.querySelector('[aria-label="Messages"]') ??
            document.body;

        const candidates = root.querySelectorAll('a[href], [role="link"]');
        for (const node of candidates) {
            const raw =
                (node.tagName === "A" ? node.getAttribute("href") : null) ||
                node.getAttribute?.("href") ||
                node.textContent ||
                "";

            const urls = extractUrls(raw);
            if (urls.length === 0) continue;

            const threats = urls.map(analyzeUrl).filter(Boolean);
            if (threats.length === 0) continue;

            const worst = worstLevel(threats);
            const label = makeShortLabel(threats);
            const tooltip = makeTooltip(threats);

            const container =
                node.closest?.('[data-list-item-id]') ??
                node.closest?.('li') ??
                node.closest?.('[class*="message"]') ??
                null;
            if (!container) continue;

            container.setAttribute('data-ipgrab', worst);
            container.setAttribute('data-ipgrab-label', label);
            if (tooltip) container.setAttribute('title', tooltip);
            this._recolorLinks(container);
        }
    }

    _scanChannel(channelId) {
        try {
            const msgs = this._messageStore?.getMessages?.(channelId);
            const arr = msgs?.toArray?.() ?? msgs?._array ?? msgs;
            if (!Array.isArray(arr)) return;
            for (const message of arr) {
                this._handle(message, false);
            }
        } catch (e) {
            console.warn("[IPGrabberDetector] Failed to scan channel messages", e);
        }
    }


    _handle(message, edited) {
        const cfg = this._config();
        const { id, content, channel_id, author } = message;
        if (!content && !message?.embeds?.length) return;
        if (cfg.ignoreBots && author?.bot) return;

        const urls = [];
        if (content) urls.push(...extractUrls(content));

        if (Array.isArray(message?.embeds)) {
            for (const emb of message.embeds) {
                if (!emb) continue;
                if (typeof emb.url === "string") urls.push(emb.url);
                if (typeof emb.title === "string") urls.push(...extractUrls(emb.title));
                if (typeof emb.description === "string") urls.push(...extractUrls(emb.description));
                if (Array.isArray(emb.fields)) {
                    for (const f of emb.fields) {
                        if (typeof f?.value === "string") urls.push(...extractUrls(f.value));
                    }
                }
            }
        }

        const threats = urls.map(analyzeUrl).filter(Boolean);

        if (threats.length > 0) {
            console.log("[IPGrabberDetector] threats", { messageId: id, worst: worstLevel(threats), threats });
            this._debugToast(`IPGrabberDetector: detected ${worstLevel(threats)} (${threats.length})`, worstLevel(threats) === "danger" ? "error" : "warning");
        }

        if (threats.length === 0) {
            if (edited) this._clearHighlight(id);
            return;
        }

        const worst = worstLevel(threats);

        if (cfg.highlight) {
            const label = makeShortLabel(threats);
            const tooltip = makeTooltip(threats);
            this._highlightMessage(id, worst, label, tooltip);
        }
    }


    _sendWarning(channelId, threats, edited) {
        const embed = buildWarningEmbed(threats, edited);
        try {
            const { receiveMessage } = BdApi.Webpack.getModule(m => m?.receiveMessage);
            receiveMessage(channelId, {
                id: makeSnowflake(),
                channel_id: channelId,
                type: 0,
                content: "",
                embeds: [embed],
                author: {
                    id: "0",
                    username: "IPGrabberDetector",
                    discriminator: "0000",
                    avatar: null,
                    bot: true,
                },
                timestamp: new Date().toISOString(),
                mention_everyone: false,
                mentions: [],
                mention_roles: [],
                attachments: [],
                pinned: false,
                tts: false,
            });
        } catch {
            BdApi.UI.showNotice(
                `⚠️ IPGrabberDetector: ${threats.length} suspicious link${threats.length > 1 ? "s" : ""} detected in this channel!`,
                { type: "danger", timeout: 8000 }
            );
        }
    }


    _getMessageElement(messageId) {
        const listItem =
            document.querySelector(`[data-list-item-id$="${messageId}"]`) ??
            document.querySelector(`[data-list-item-id*="${messageId}"]`);
        if (listItem) return listItem;

        const inner = document.querySelector(`[id$="-${messageId}"]`);
        if (!inner) return null;

        return (
            inner.closest?.("[data-list-item-id]") ??
            inner.closest?.("li") ??
            inner
        );
    }

    _highlightMessage(messageId, level, label, tooltipText) {
        this._highlighted.add(messageId);
        let attempts = 0;
        const tryIt = () => {
            const el = this._getMessageElement(messageId);
            if (el) {
                el.setAttribute("data-ipgrab", level);
                el.setAttribute("data-ipgrab-label", label);
                if (tooltipText) el.setAttribute("title", tooltipText);
                this._recolorLinks(el);
            } else if (++attempts < 12) {
                setTimeout(tryIt, 150);
            }
        };
        tryIt();
    }

    _clearHighlight(messageId) {
        this._highlighted.delete(messageId);
        const el = this._getMessageElement(messageId);
        if (!el) return;
        el.removeAttribute("data-ipgrab");
        el.removeAttribute("data-ipgrab-label");
        el.removeAttribute("title");
        el.querySelectorAll('a, [role="link"], [class*="anchor"], [class*="link"]').forEach(link => {
            link.style.removeProperty("color");
            link.style.removeProperty("text-decoration");
            link.style.removeProperty("text-decoration-color");
        });
    }


    _injectStyles() {
        if (document.getElementById(STYLE_ID)) return;
        const el = document.createElement("style");
        el.id = STYLE_ID;
        el.textContent = CSS;
        document.head.appendChild(el);
    }

    _removeStyles() {
        document.getElementById(STYLE_ID)?.remove();
    }

    _noOp() {}
};
