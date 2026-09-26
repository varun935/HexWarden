import "dotenv/config";
import express from "express";
import cors from "cors";
import multer from "multer";
import { analyze } from "./firmware.js";
import { blockchain, status } from "./blockchain.js";

const app = express();
const upload = multer({ dest: process.env.UPLOAD_DIR ?? "/tmp/hexwarden-dlt" });
app.use(cors());
app.use(express.json());

app.post("/api/firmware/analyze", upload.single("firmware"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "firmware multipart field is required" });
  try { return res.json(await analyze(req.file.path)); }
  catch (error) { return res.status(422).json({ error: String(error) }); }
});

app.post("/api/firmware/approve", upload.single("firmware"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "firmware multipart field is required" });
  if (!req.body.deviceModel || !req.body.version) return res.status(400).json({ error: "deviceModel and version are required" });
  try {
    const result = await analyze(req.file.path);
    if (result.verdict !== "CLEAN") return res.status(422).json({ error: "Only CLEAN firmware can be attested", analysis: result });
    const { contract } = blockchain();
    const tx = await contract.approveFirmware(`0x${result.sha256}`, req.body.deviceModel, req.body.version);
    const receipt = await tx.wait();
    return res.json({ analysis: result, transactionHash: receipt.hash, hash: result.sha256 });
  } catch (error) { return res.status(422).json({ error: String(error) }); }
});

app.get("/api/firmware/:hash", async (req, res) => {
  try {
    const model = String(req.query.deviceModel ?? "");
    const { contract } = blockchain();
    const record = await contract.getFirmware(`0x${req.params.hash.replace(/^0x/, "")}`);
    if (record.timestamp === 0n) return res.status(404).json({ error: "Firmware is not registered" });
    return res.json({ hash: record[0], deviceModel: record[1], version: record[2], attester: record[3], timestamp: Number(record[4]), approved: record[5] && (!model || await contract.isApproved(record[0], model)) });
  } catch (error) { return res.status(404).json({ error: String(error) }); }
});

app.post("/api/firmware/:hash/revoke", async (req, res) => {
  try { const { contract } = blockchain(); const tx = await contract.revokeFirmware(`0x${req.params.hash.replace(/^0x/, "")}`); const receipt = await tx.wait(); return res.json({ transactionHash: receipt.hash, status: "REVOKED" }); }
  catch (error) { return res.status(422).json({ error: String(error) }); }
});

app.get("/api/blockchain/status", async (_req, res) => {
  try { return res.json(await status()); } catch (error) { return res.status(503).json({ error: String(error) }); }
});

const port = Number(process.env.PORT ?? 4000);
app.listen(port, () => console.log(`HexWarden DLT backend listening on http://localhost:${port}`));