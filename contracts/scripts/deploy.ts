import { ethers } from "hardhat";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

async function main() {
  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("FirmwareRegistry");
  const registry = await factory.deploy(deployer.address);
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const deployment = { address, chainId: 1337, deployer: deployer.address };
  writeFileSync(resolve(__dirname, "../deployment.json"), JSON.stringify(deployment, null, 2));
  console.log(JSON.stringify(deployment));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});