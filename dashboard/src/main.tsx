import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:4000";
type Status = { blockNumber: number; chainId: number; contractAddress: string; connectedNodes: { url: string; online: boolean }[] };
type ApiError = { error: string };

function App() {
  const [status, setStatus] = useState<Status>();
  const [statusError, setStatusError] = useState<string>();
  const [hash, setHash] = useState("");
  const [record, setRecord] = useState<any>();
  useEffect(() => {
    fetch(`${API}/api/blockchain/status`)
      .then(async (response) => {
        const body = await response.json() as Status | ApiError;
        if (!response.ok) throw new Error("error" in body ? body.error : "Blockchain status unavailable");
        setStatus(body as Status);
      })
      .catch((error: Error) => setStatusError(error.message));
  }, []);
  async function check() {
    if (!hash) return;
    const response = await fetch(`${API}/api/firmware/${hash}`);
    setRecord(await response.json());
  }
  const nodes = status?.connectedNodes ?? [];
  return <main><header><p className="eyebrow">HEXWARDEN / TRUST FABRIC</p><h1>Firmware Registry</h1><p className="lede">A shared attestation ledger for firmware that passed HexWarden analysis.</p></header>
    {statusError && <p className="api-error">Blockchain status unavailable. Start Besu and deploy the contract, then reload this page.</p>}
    <section className="grid"><article><h2>Validators</h2>{["Vendor", "Security Laboratory", "Utility", "CSIRT"].map((name, i) => <div className="validator" key={name}><span>{name}</span><b className={nodes[i]?.online ? "online" : "unknown"}>● {nodes[i]?.online ? "ONLINE" : "OFFLINE"}</b></div>)}</article>
      <article><h2>Consensus</h2><strong className="consensus">QBFT</strong><p>Latest block <b>{status?.blockNumber ?? "--"}</b></p><p>Chain ID <b>{status?.chainId ?? "--"}</b></p></article></section>
    <section className="lookup"><h2>Check firmware</h2><div><input value={hash} onChange={(e) => setHash(e.target.value)} placeholder="SHA-256 hash"/><button onClick={check}>Query ledger</button></div>{record && <pre>{JSON.stringify(record, null, 2)}</pre>}</section>
  </main>;
}
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);