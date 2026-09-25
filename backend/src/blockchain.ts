import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ABI = [
  "function approveFirmware(bytes32,string,string)",
  "function revokeFirmware(bytes32)",
  "function isApproved(bytes32,string) view returns (bool)",
  "function getFirmware(bytes32) view returns (bytes32,string,string,address,uint256,bool)",
  "event FirmwareApproved(bytes32 indexed firmwareHash,string deviceModel,string version,address indexed attester,uint256 timestamp)",
  "event FirmwareRevoked(bytes32 indexed firmwareHash,address indexed revoker,uint256 timestamp)"
];

const rpcUrl = process.env.BESU_RPC_URL ?? "http://127.0.0.1:8545";
const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
const deploymentPath = process.env.DEPLOYMENT_FILE ?? resolve(process.cwd(), "../contracts/deployment.json");

export function blockchain() {
  if (!privateKey) throw new Error("DEPLOYER_PRIVATE_KEY is required");
  const deployment = JSON.parse(readFileSync(deploymentPath, "utf8")) as { address: string };
  const provider = new JsonRpcProvider(rpcUrl);
  const signer = new Wallet(privateKey, provider);
  return { provider, contract: new Contract(deployment.address, ABI, signer), address: deployment.address };
}

export async function status() {
  const { provider, address } = blockchain();
  const network = await provider.getNetwork();
  const block = await provider.getBlockNumber();
  const nodeUrls = (process.env.BESU_RPC_URLS ?? rpcUrl).split(",");
  const connectedNodes = await Promise.all(nodeUrls.map(async (url) => {
    try { await new JsonRpcProvider(url).getBlockNumber(); return { url, online: true }; }
    catch { return { url, online: false }; }
  }));
  return { blockNumber: block, chainId: Number(network.chainId), contractAddress: address, connectedNodes };
}

export { ABI };