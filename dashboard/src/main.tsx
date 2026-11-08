import { StrictMode, useEffect, useState } from "react";
import type { ChangeEvent, FormEvent, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import hexWardenLogo from "../../web/static/hexwarden.png";
import "./style.css";

const API = import.meta.env.VITE_API_URL ?? "";
type Status = {
  blockNumber: number;
  chainId: number;
  contractAddress: string;
  connectedNodes: { url: string; online: boolean }[];
};
type FirmwareRecord = {
  hash: string;
  deviceModel: string;
  version: string;
  attester: string;
  timestamp: number;
  approved: boolean;
};
type ApiError = { error: string };
type AuditEntry = {
  id: string;
  at: string;
  kind: "request" | "success" | "warning" | "error";
  message: string;
};
type AuditResponse = { entries: AuditEntry[] };
type SceneProps = {
  id: string;
  number: string;
  eyebrow: string;
  title: string;
  description?: string;
  className?: string;
  children: ReactNode;
};

function CircuitBoard() {
  return (
    <div className="ledger-pcb-stage" role="img" aria-label="Animated 3D illustration of a firmware analysis circuit board">
      <div className="ledger-pcb-shadow" />
      <div className="ledger-pcb-board">
        <div className="ledger-pcb-board-base" />
        <svg
          className="ledger-pcb-circuit"
          viewBox="0 0 800 500"
          role="presentation"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id="pcb-surface" x1="0" x2="1" y1="0" y2="1">
              <stop offset="0" stopColor="#193a37" />
              <stop offset=".52" stopColor="#102a29" />
              <stop offset="1" stopColor="#0b1c20" />
            </linearGradient>
            <linearGradient id="pcb-edge" x1="0" x2="1" y1="0" y2="1">
              <stop offset="0" stopColor="#8ce7ce" stopOpacity=".65" />
              <stop offset=".46" stopColor="#4ed2b0" stopOpacity=".18" />
              <stop offset="1" stopColor="#6fa9b2" stopOpacity=".42" />
            </linearGradient>
            <filter id="pcb-glow" x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <path
            className="ledger-pcb-surface"
            d="M92 48h574l64 62v277l-58 58H128l-64-60V111z"
            fill="url(#pcb-surface)"
            stroke="url(#pcb-edge)"
            strokeWidth="3"
          />
          <path
            className="ledger-pcb-surface-inset"
            d="M112 68h544l54 52v252l-49 51H136l-52-52V120z"
            fill="none"
            stroke="#83e2c6"
            strokeOpacity=".16"
            strokeWidth="1.5"
          />
          <g className="ledger-pcb-traces">
            <path d="M176 136h126v54h42" />
            <path d="M174 166h82v92h86" />
            <path d="M174 197h54v108h106" />
            <path d="M180 340h104v-51h56" />
            <path d="M420 150h82v-43h150" />
            <path d="M435 182h102v-56h112" />
            <path d="M430 300h101v74h103" />
            <path d="M418 328h75v79h100" />
            <path d="M544 210h119" />
            <path d="M544 236h100v53h30" />
            <path d="M304 98v-20h-78" />
            <path d="M344 370v54h-87" />
            <path d="M568 163v-25h76" />
            <path d="M568 330v35" />
          </g>
          <g className="ledger-pcb-pads">
            <circle cx="176" cy="136" r="5" />
            <circle cx="174" cy="166" r="5" />
            <circle cx="174" cy="197" r="5" />
            <circle cx="180" cy="340" r="5" />
            <circle cx="652" cy="107" r="5" />
            <circle cx="654" cy="126" r="5" />
            <circle cx="654" cy="374" r="5" />
            <circle cx="593" cy="407" r="5" />
            <circle cx="226" cy="78" r="5" />
            <circle cx="257" cy="424" r="5" />
          </g>
          <g className="ledger-pcb-silkscreen">
            <text x="137" y="111">HW / TRUST FABRIC</text>
            <text x="589" y="347">REV 04</text>
            <text x="139" y="386">SECURE BOOT</text>
          </g>
          <g className="ledger-pcb-chip ledger-pcb-chip-main">
            <rect x="348" y="160" width="172" height="166" rx="12" />
            <rect className="ledger-pcb-chip-inset" x="359" y="171" width="150" height="144" rx="8" />
            <path className="ledger-pcb-chip-pins" d="M362 153v-12m20 12v-12m20 12v-12m20 12v-12m20 12v-12m20 12v-12m20 12v-12m20 12v-12m-160 185v12m20-12v12m20-12v12m20-12v12m20-12v12m20-12v12m20-12v12m20-12v12m-182-150h-12m12 20h-12m12 20h-12m12 20h-12m12 20h-12m12 20h-12m12 20h-12m12 20h-12m184-140h12m-12 20h12m-12 20h12m-12 20h12m-12 20h12m-12 20h12m-12 20h12m-12 20h12" />
            <text x="434" y="229" textAnchor="middle">HEXWARDEN</text>
            <text className="ledger-pcb-chip-subtitle" x="434" y="255" textAnchor="middle">SECURE ELEMENT</text>
            <path className="ledger-pcb-chip-mark" d="m421 276 10 10 19-22" />
          </g>
          <g className="ledger-pcb-chip ledger-pcb-chip-small ledger-pcb-chip-left">
            <rect x="213" y="248" width="78" height="70" rx="7" />
            <rect className="ledger-pcb-chip-inset" x="221" y="256" width="62" height="54" rx="4" />
            <path className="ledger-pcb-chip-pins" d="M225 244v-8m18 8v-8m18 8v-8m18 8v-8m-54 86v8m18-8v8m18-8v8m18-8v8m-74-58h-8m8 16h-8m8 16h-8m86-24h8m-8 16h8m-8 16h8" />
          </g>
          <g className="ledger-pcb-chip ledger-pcb-chip-small ledger-pcb-chip-right">
            <rect x="548" y="258" width="72" height="64" rx="7" />
            <rect className="ledger-pcb-chip-inset" x="556" y="266" width="56" height="48" rx="4" />
            <path className="ledger-pcb-chip-pins" d="M562 254v-8m18 8v-8m18 8v-8m18 8v-8m-54 80v8m18-8v8m18-8v8m18-8v8m-68-46h-8m8 16h-8m8 16h-8m80-24h8m-8 16h8m-8 16h8" />
          </g>
          <g className="ledger-pcb-components">
            <rect x="218" y="128" width="24" height="12" rx="2" />
            <rect x="220" y="145" width="33" height="12" rx="2" />
            <rect x="561" y="158" width="32" height="12" rx="2" />
            <rect x="589" y="180" width="22" height="12" rx="2" />
            <rect x="224" y="351" width="32" height="12" rx="2" />
            <rect x="552" y="352" width="26" height="12" rx="2" />
            <circle cx="300" cy="235" r="8" />
            <circle cx="300" cy="328" r="7" />
            <circle cx="530" cy="335" r="7" />
          </g>
          <g className="ledger-pcb-leds" filter="url(#pcb-glow)">
            <circle className="ledger-pcb-led ledger-pcb-led-one" cx="650" cy="210" r="4" />
            <circle className="ledger-pcb-led ledger-pcb-led-two" cx="650" cy="228" r="4" />
            <circle className="ledger-pcb-led ledger-pcb-led-three" cx="148" cy="285" r="4" />
          </g>
        </svg>
        <div className="ledger-pcb-board-shadow" />
      </div>
      <span className="ledger-pcb-label ledger-pcb-label-top">HW / BOARD 001</span>
      <span className="ledger-pcb-label ledger-pcb-label-bottom">SIGNAL PATH / VERIFIED</span>
      <span className="ledger-pcb-coordinate">40°42′ N — 74°00′ W</span>
    </div>
  );
}

const validatorNames = ["Vendor", "Security Laboratory", "Utility", "CSIRT"];

function Scene({
  id,
  number,
  eyebrow,
  title,
  description,
  className = "",
  children,
}: SceneProps) {
  return (
    <section
      className={`ledger-scene ${className}`}
      id={id}
      aria-labelledby={`${id}-title`}
    >
      <div className="ledger-scene-inner">
        <div className="ledger-scene-topline">
          <span className="ledger-eyebrow">{eyebrow}</span>
          <span className="ledger-scene-number">{number} / 06</span>
        </div>
        <div className="ledger-scene-heading">
          <h2 id={`${id}-title`}>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {children}
      </div>
    </section>
  );
}

function App() {
  const [status, setStatus] = useState<Status>();
  const [statusError, setStatusError] = useState<string>();
  const [hash, setHash] = useState("");
  const [record, setRecord] = useState<FirmwareRecord | ApiError>();
  const [querying, setQuerying] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditError, setAuditError] = useState<string>();

  async function refreshAudit() {
    try {
      const response = await fetch(`${API}/api/audit?limit=40`);
      if (!response.ok) throw new Error(`Audit service returned HTTP ${response.status}`);
      const body = (await response.json()) as AuditResponse;
      setAudit(body.entries);
      setAuditError(undefined);
    } catch (error) {
      setAuditError(error instanceof Error ? error.message : "Audit history unavailable");
    }
  }

  useEffect(() => {
    let active = true;
    const refreshStatus = async () => {
      try {
        const response = await fetch(`${API}/api/blockchain/status`);
        const body = (await response.json()) as Status | ApiError;
        if (!response.ok || "error" in body) {
          throw new Error("error" in body ? body.error : "Blockchain status unavailable");
        }
        if (!active) return;
        setStatus(body);
        setStatusError(undefined);
        void refreshAudit();
      } catch (error) {
        if (!active) return;
        setStatusError(error instanceof Error ? error.message : "Blockchain status unavailable");
        void refreshAudit();
      }
    };

    void refreshStatus();
    void refreshAudit();
    const timer = window.setInterval(() => void refreshStatus(), 12000);
    const auditTimer = window.setInterval(() => void refreshAudit(), 10000);
    return () => {
      active = false;
      window.clearInterval(timer);
      window.clearInterval(auditTimer);
    };
  }, []);

  async function check(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hash.trim()) return;

    const normalizedHash = hash.trim().replace(/^0x/i, "");
    setQuerying(true);
    setRecord(undefined);
    try {
      const response = await fetch(`${API}/api/firmware/${normalizedHash}`);
      const body = (await response.json()) as FirmwareRecord | ApiError;
      if (!response.ok) {
        const message =
          "error" in body ? body.error : `Ledger query returned HTTP ${response.status}`;
        setRecord({ error: message });
        return;
      }
      setRecord(body as FirmwareRecord);
    } catch (error) {
      setRecord({ error: error instanceof Error ? error.message : "Firmware lookup failed" });
    } finally {
      setQuerying(false);
      void refreshAudit();
    }
  }

  function updateHash(event: ChangeEvent<HTMLInputElement>) {
    setHash(event.currentTarget.value);
  }

  const nodes = status?.connectedNodes ?? [];
  const onlineCount = nodes.filter((node) => node.online).length;
  const isEmbedded = document.querySelector(".ledger-mount") !== null;

  return (
    <main className="ledger-workspace" aria-label="Firmware trust ledger">
      {!isEmbedded && (
        <header className="ledger-brand">
          <a href="/" aria-label="HexWarden home">
            <img src={hexWardenLogo} alt="HexWarden" />
          </a>
        </header>
      )}
      <div className="ledger-story">
        <Scene
          id="ledger-hero"
          number="01"
          eyebrow="HEXWARDEN / TRUST FABRIC"
          title="Trust starts at the source."
          description="Every device begins with a board. Every trusted board begins with a story you can verify."
          className="ledger-scene-hero"
        >
          <div className="ledger-hero-layout">
            <div className="ledger-hero-copy">
              <p className="ledger-hero-kicker">SECURITY, DOWN TO THE SILICON.</p>
              <a className="ledger-primary-link" href="#ledger-board">
                See what powers trust <span aria-hidden="true">↗</span>
              </a>
            </div>
            <div className="ledger-object-stage" aria-hidden="true">
              <div className="ledger-object-orbit ledger-object-orbit-one" />
              <div className="ledger-object-orbit ledger-object-orbit-two" />
              <div className="ledger-object-glow" />
              <div className="ledger-object">
                <div className="ledger-object-edge" />
                <div className="ledger-object-mark">H</div>
                <span className="ledger-object-caption">HEXWARDEN / HW-01</span>
              </div>
              <span className="ledger-object-coordinate">SIGNAL / 0x7F</span>
            </div>
          </div>
          <div className="ledger-hero-foot">
            <span>ONE HASH. A NETWORK OF PROOF.</span>
            <span className="ledger-scroll-cue"><i /> SCROLL TO EXPLORE</span>
          </div>
        </Scene>

        <Scene
          id="ledger-board"
          number="02"
          eyebrow="THE HARDWARE / UNDER THE HOOD"
          title="Built on a foundation you can see."
          description="A closer look at the signals, secure elements, and firmware that make a device trustworthy."
          className="ledger-scene-board"
        >
          <div className="ledger-board-story">
            <div className="ledger-board-sticky">
              <CircuitBoard />
            </div>
            <div className="ledger-board-steps">
              <article className="ledger-board-step">
                <span>01 / THE BOARD</span>
                <h3>A foundation for trust.</h3>
                <p>Follow the copper paths from the edge of the board to the secure element at its center.</p>
              </article>
              <article className="ledger-board-step">
                <span>02 / SECURE ELEMENT</span>
                <h3>Identity, held in hardware.</h3>
                <p>The chip anchors device identity. Its keys stay protected while firmware is checked.</p>
              </article>
              <article className="ledger-board-step">
                <span>03 / FIRMWARE SIGNAL</span>
                <h3>Every trace tells a story.</h3>
                <p>Signal paths carry the verified image from boot through analysis and attestation.</p>
              </article>
              <article className="ledger-board-step">
                <span>04 / VERIFIED</span>
                <h3>From silicon to shared proof.</h3>
                <p>One measured fingerprint becomes a record every validator can independently confirm.</p>
              </article>
            </div>
          </div>
        </Scene>

        <Scene
          id="ledger-layers"
          number="03"
          eyebrow="THE VERIFICATION STACK"
          title="Four layers. One clear answer."
          description="From a binary fingerprint to a permanent, shared record. Nothing gets lost between the layers."
          className="ledger-scene-layers"
        >
          <div className="ledger-layer-layout">
            <div className="ledger-layer-stack" aria-label="Firmware verification layers">
              {[
                ["01", "Analysis", "Signals surfaced"],
                ["02", "Attestation", "Identity confirmed"],
                ["03", "Consensus", "Validators aligned"],
                ["04", "Provenance", "Record preserved"],
              ].map(([number, name, detail], index) => (
                <div className={`ledger-layer-row ledger-layer-row-${index + 1}`} key={number}>
                  <span>{number}</span>
                  <strong>{name}</strong>
                  <small>{detail}</small>
                  <i aria-hidden="true">↗</i>
                </div>
              ))}
            </div>
            <p className="ledger-layer-note">
              One continuous chain of custody, anchored to the firmware itself.
            </p>
          </div>
        </Scene>

        <Scene
          id="ledger-validators"
          number="04"
          eyebrow="LIVE / QBFT NETWORK"
          title="Agreement, in real time."
          description="Independent validators maintain a shared source of truth for every attestation."
          className="ledger-scene-network"
        >
          <div className="ledger-network-layout">
            <div className="ledger-network-list">
              <div className="ledger-network-list-heading">
                <span>VALIDATOR</span>
                <span>
                  {status ? `${onlineCount} OF ${validatorNames.length} ONLINE` : "CONNECTING"}
                </span>
              </div>
              {validatorNames.map((name, index) => (
                <div className="ledger-validator-row" key={name}>
                  <span className="ledger-validator-index">0{index + 1}</span>
                  <span className="ledger-validator-name">{name}</span>
                  <span
                    className={`ledger-validator-status ${nodes[index]?.online ? "is-online" : ""}`}
                  >
                    <i aria-hidden="true" />
                    {nodes[index]?.online ? "ONLINE" : status ? "OFFLINE" : "CHECKING"}
                  </span>
                </div>
              ))}
            </div>
            <div className="ledger-network-aside">
              <div className="ledger-network-stat">
                <span>LATEST BLOCK</span>
                <strong>{status?.blockNumber ?? "--"}</strong>
              </div>
              <div className="ledger-network-stat">
                <span>CHAIN ID</span>
                <strong>{status?.chainId ?? "--"}</strong>
              </div>
              <div className="ledger-contract">
                <span>REGISTRY CONTRACT</span>
                <code>{status?.contractAddress ?? "Waiting for RPC"}</code>
              </div>
            </div>
          </div>
          {statusError && (
            <p className="ledger-status-error" role="status">
              Network status unavailable: {statusError}
            </p>
          )}
        </Scene>

        <Scene
          id="ledger-verify"
          number="05"
          eyebrow="FIRMWARE / LOOKUP"
          title="Proof you can look up."
          description="Check an attestation by its SHA-256 fingerprint. A single hash connects the file to its on-chain record."
          className="ledger-scene-verify"
        >
          <div className="ledger-verify-layout">
            <section className="ledger-lookup" aria-labelledby="ledger-lookup-title">
              <div className="ledger-subsection-heading">
                <span>01 — FIRMWARE RECORD</span>
                <h3 id="ledger-lookup-title">Verify a hash.</h3>
              </div>
              <form onSubmit={check}>
                <label htmlFor="ledger-firmware-hash">SHA-256 FINGERPRINT</label>
                <div className="ledger-input-row">
                  <input
                    id="ledger-firmware-hash"
                    value={hash}
                    onChange={updateHash}
                    placeholder="Paste firmware hash"
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <button type="submit" disabled={querying || !hash.trim()}>
                    {querying ? "Checking…" : "Verify"}
                    <span aria-hidden="true">↗</span>
                  </button>
                </div>
              </form>
              {record && (
                <pre className="ledger-record" role="status">
                  {JSON.stringify(record, null, 2)}
                </pre>
              )}
            </section>
            <div className="ledger-lookup-aside">
              <span>SHA-256 / ON-CHAIN ATTESTATION</span>
              <strong>One fingerprint.<br />A complete history.</strong>
              <p>Validated records are linked to immutable network activity, not just a local file.</p>
            </div>
          </div>
        </Scene>

        <Scene
          id="ledger-audit"
          number="06"
          eyebrow="LIVE / ACTIVITY AUDIT"
          title="Every step, accounted for."
          description="Follow requests, successful attestations, and network warnings in one transparent record."
          className="ledger-scene-audit"
        >
          <div className="ledger-audit-layout">
            <div className="ledger-audit-intro">
              <div className="ledger-subsection-heading">
                <span>NETWORK / EVENT STREAM</span>
                <h3 id="ledger-audit-title">A living history.</h3>
              </div>
              <p>New events are recorded as the network works. The latest entries stay close, the full provenance stays on chain.</p>
              <a className="ledger-back-to-top" href="#ledger-hero">
                Back to the beginning <span aria-hidden="true">↑</span>
              </a>
            </div>
            <ol className="ledger-audit-list" aria-live="polite" aria-labelledby="ledger-audit-title">
              {audit.length ? (
                audit.map((entry) => (
                  <li className={`ledger-audit-entry ${entry.kind}`} key={entry.id}>
                    <time dateTime={entry.at}>{new Date(entry.at).toLocaleTimeString()}</time>
                    <span>{entry.message}</span>
                  </li>
                ))
              ) : (
                <li className="ledger-audit-empty">{auditError ?? "Waiting for network activity"}</li>
              )}
            </ol>
          </div>
        </Scene>
      </div>
    </main>
  );
}

createRoot(document.getElementById("ledger-root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
