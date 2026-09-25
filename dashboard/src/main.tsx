import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:4000";
type Status = { blockNumber: number; chainId: number; contractAddress: string; connectedNodes: { url: string; online: boolean }[] };

function App() {
  const [status, setStatus] = useState<Status>();
  const [hash, setHash] = useState("");
  const [record, setRecord] = useState<any>();
  useEffect(() => { fetch(`${API}/api/blockchain/status`).then((r) => r.json()).then(setStatus).catch(() => undefined); }, []);
  async function check() { if (hash) setRecord(await fetch(`${API}/api/firmware/${hash}`).then((r) => r.json())); }
  return <main><header><p className="eyebrow">HEXWARDEN / TRUST FABRIC</p><h1>Firmware Registry</h1><p className="lede">A shared attestation ledger for firmware that passed HexWarden analysis.</p></header>
    <section className="grid"><article><h2>Validators</h2>{["Vendor", "Security Laboratory", "Utility", "CSIRT"].map((name, i) => <div className="validator" key={name}><span>{name}</span><b className={status?.connectedNodes[i]?.online ? "online" : "unknown"}>● {status?.connectedNodes[i]?.online ? "ONLINE" : "UNKNOWN"}</b></div>)}</article>
      <article><h2>Consensus</h2><strong className="consensus">QBFT</strong><p>Latest block <b>{status?.blockNumber ?? "--"}</b></p><p>Chain ID <b>{status?.chainId ?? "--"}</b></p></article></section>
    <section className="lookup"><h2>Check firmware</h2><div><input value={hash} onChange={(e) => setHash(e.target.value)} placeholder="SHA-256 hash"/><button onClick={check}>Query ledger</button></div>{record && <pre>{JSON.stringify(record, null, 2)}</pre>}</section>
  </main>;
}
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);