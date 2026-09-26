import { FormEvent, StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_URL ?? "";
type Status = { blockNumber: number; chainId: number; contractAddress: string; connectedNodes: { url: string; online: boolean }[] };
type FirmwareRecord = { hash: string; deviceModel: string; version: string; attester: string; timestamp: number; approved: boolean };
type ApiError = { error: string };
type AuditEntry = { id: string; at: string; kind: "request" | "success" | "warning" | "error"; message: string };
type AuditResponse = { entries: AuditEntry[] };

const validatorNames = ["Vendor", "Security Laboratory", "Utility", "CSIRT"];

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
      const body = await response.json() as AuditResponse;
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
        const body = await response.json() as Status | ApiError;
        if (!response.ok || "error" in body) throw new Error("error" in body ? body.error : "Blockchain status unavailable");
        if (!active) return;
        setStatus(body);
        setStatusError(undefined);
        void refreshAudit();
      } catch (error) {
        if (!active) return;
        const message = error instanceof Error ? error.message : "Blockchain status unavailable";
        setStatusError(message);
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
    if (!hash) return;
    const normalizedHash = hash.trim().replace(/^0x/i, "");
    setQuerying(true);
    setRecord(undefined);
    try {
      const response = await fetch(`${API}/api/firmware/${normalizedHash}`);
      const body = await response.json() as FirmwareRecord | ApiError;
      if (!response.ok) {
        const message = "error" in body ? body.error : `Ledger query returned HTTP ${response.status}`;
        setRecord({ error: message });
        return;
      }
      setRecord(body as FirmwareRecord);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Firmware lookup failed";
      setRecord({ error: message });
    } finally {
      setQuerying(false);
      void refreshAudit();
    }
  }
  const nodes = status?.connectedNodes ?? [];
  return <div className="ledger-workspace">
    <div className="ledger-heading">
      <div><p className="ledger-eyebrow">TRUST FABRIC / LIVE NETWORK</p><h2>Firmware ledger</h2><p>Attestations and validator health for firmware cleared by HexWarden analysis.</p></div>
      <a href="#upload-card">Analyze firmware</a>
    </div>
    {statusError && <p className="ledger-error" role="status">Blockchain status unavailable: {statusError}</p>}
    <div className="ledger-overview">
      <article className="ledger-panel">
        <div className="ledger-panel-heading"><h3>Validators</h3><span className="ledger-live"><i /> LIVE</span></div>
        {validatorNames.map((name, index) => <div className="ledger-validator" key={name}><span>{name}</span><b className={nodes[index]?.online ? "is-online" : "is-offline"}>● {nodes[index]?.online ? "ONLINE" : status ? "OFFLINE" : "CHECKING"}</b></div>)}
      </article>
      <article className="ledger-panel ledger-chain">
        <h3>QBFT network</h3>
        <div className="ledger-stats"><div><span>Latest block</span><strong>{status?.blockNumber ?? "--"}</strong></div><div><span>Chain ID</span><strong>{status?.chainId ?? "--"}</strong></div></div>
        <p className="ledger-contract">Registry <code>{status?.contractAddress ?? "Waiting for RPC"}</code></p>
      </article>
    </div>
    <div className="ledger-activity-grid">
      <section className="ledger-panel ledger-lookup">
        <h3>Verify firmware record</h3>
        <form onSubmit={check}><input value={hash} onChange={(event) => setHash(event.target.value)} placeholder="SHA-256 hash" aria-label="Firmware SHA-256 hash"/><button type="submit" disabled={querying || !hash.trim()}>{querying ? "Fetching…" : "Query ledger"}</button></form>
        {record && <pre className="ledger-record">{JSON.stringify(record, null, 2)}</pre>}
      </section>
      <section className="ledger-panel ledger-audit" aria-labelledby="ledger-audit-title">
        <div className="ledger-panel-heading"><h3 id="ledger-audit-title">Activity audit</h3><span>SERVER LOG</span></div>
        <ol className="ledger-audit-list" aria-live="polite">{audit.length ? audit.map((entry) => <li className={`ledger-audit-entry ${entry.kind}`} key={entry.id}><time dateTime={entry.at}>{new Date(entry.at).toLocaleTimeString()}</time><span>{entry.message}</span></li>) : <li className="ledger-audit-empty">{auditError ?? "Waiting for server activity"}</li>}</ol>
      </section>
    </div>
  </div>;
}
createRoot(document.getElementById("ledger-root")!).render(<StrictMode><App /></StrictMode>);