import "dotenv/config";
import express from "express";
import cors from "cors";
import multer from "multer";
import { analyze } from "./firmware.js";
import { blockchain, status } from "./blockchain.js";
import { getRecentAudit, recordAudit } from "./audit.js";

const app = express();
const upload = multer({ dest: process.env.UPLOAD_DIR ?? "/tmp/hexwarden-dlt" });
app.use(cors());
app.use(express.json());

app.post("/api/firmware/analyze", upload.single("firmware"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "firmware multipart field is required" });
  recordAudit("request", `Analyzing uploaded firmware ${req.file.originalname || "image"}`);
  try {
    const result = await analyze(req.file.path);
    recordAudit(result.verdict === "CLEAN" ? "success" : "warning", `Firmware analysis complete: ${result.verdict} (${result.sha256.slice(0, 12)}…)`);
    return res.json(result);
  } catch (error) {
    recordAudit("error", `Firmware analysis failed: ${String(error)}`);
    return res.status(422).json({ error: String(error) });
  }
});

app.post("/api/firmware/approve", upload.single("firmware"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "firmware multipart field is required" });
  if (!req.body.deviceModel || !req.body.version) return res.status(400).json({ error: "deviceModel and version are required" });
  recordAudit("request", `Analyzing firmware for ${req.body.deviceModel} ${req.body.version} attestation`);
  try {
    const result = await analyze(req.file.path);
    if (result.verdict !== "CLEAN") {
      recordAudit("warning", `Attestation rejected: firmware verdict ${result.verdict}`);
      return res.status(422).json({ error: "Only CLEAN firmware can be attested", analysis: result });
    }
    const { contract } = blockchain();
    const tx = await contract.approveFirmware(`0x${result.sha256}`, req.body.deviceModel, req.body.version);
    const receipt = await tx.wait();
    recordAudit("success", `Firmware attested for ${req.body.deviceModel} ${req.body.version} in transaction ${receipt.hash}`);
    return res.json({ analysis: result, transactionHash: receipt.hash, hash: result.sha256 });
  } catch (error) {
    recordAudit("error", `Firmware attestation failed: ${String(error)}`);
    return res.status(422).json({ error: String(error) });
  }
});

app.get("/api/firmware/:hash", async (req, res) => {
  const shortHash = req.params.hash.slice(0, 12);
  recordAudit("request", `Fetching firmware ${shortHash}… from blockchain`);
  try {
    const model = String(req.query.deviceModel ?? "");
    const { contract } = blockchain();
    const record = await contract.getFirmware(`0x${req.params.hash.replace(/^0x/, "")}`);
    if (record.timestamp === 0n) {
      recordAudit("warning", `Firmware ${shortHash}… is not registered`);
      return res.status(404).json({ error: "Firmware is not registered" });
    }
    const approved = record[5] && (!model || await contract.isApproved(record[0], model));
    recordAudit(approved ? "success" : "warning", `Firmware ${shortHash}… ledger result: ${approved ? "approved" : model && record[5] ? "model mismatch" : "revoked"}`);
    return res.json({ hash: record[0], deviceModel: record[1], version: record[2], attester: record[3], timestamp: Number(record[4]), approved });
  } catch (error) {
    recordAudit("error", `Firmware lookup ${shortHash}… failed: ${String(error)}`);
    return res.status(404).json({ error: String(error) });
  }
});

app.post("/api/firmware/:hash/revoke", async (req, res) => {
  const shortHash = req.params.hash.slice(0, 12);
  recordAudit("request", `Submitting revocation for firmware ${shortHash}…`);
  try {
    const { contract } = blockchain();
    const tx = await contract.revokeFirmware(`0x${req.params.hash.replace(/^0x/, "")}`);
    const receipt = await tx.wait();
    recordAudit("success", `Firmware ${shortHash}… revoked in transaction ${receipt.hash}`);
    return res.json({ transactionHash: receipt.hash, status: "REVOKED" });
  } catch (error) {
    recordAudit("error", `Firmware revocation ${shortHash}… failed: ${String(error)}`);
    return res.status(422).json({ error: String(error) });
  }
});

app.get("/api/blockchain/status", async (_req, res) => {
  recordAudit("request", "Fetching blockchain status from Besu validators");
  try {
    const result = await status();
    const online = result.connectedNodes.filter((node) => node.online).length;
    recordAudit(online === result.connectedNodes.length ? "success" : "warning", `Block ${result.blockNumber} received; ${online}/${result.connectedNodes.length} validators responding`);
    return res.json(result);
  } catch (error) {
    recordAudit("error", `Blockchain status request failed: ${String(error)}`);
    return res.status(503).json({ error: String(error) });
  }
});

app.get("/api/audit", (req, res) => {
  const requestedLimit = Number(req.query.limit ?? 40);
  const limit = Number.isFinite(requestedLimit) ? Math.floor(requestedLimit) : 40;
  return res.json({ entries: getRecentAudit(limit) });
});

const port = Number(process.env.PORT ?? 4000);
app.listen(port, () => {
  recordAudit("success", "HexWarden blockchain API started");
  console.log(`HexWarden DLT backend listening on http://localhost:${port}`);
});