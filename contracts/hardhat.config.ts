import "@nomicfoundation/hardhat-toolbox";
import { HardhatUserConfig } from "hardhat/config";
import dotenv from "dotenv";
import { resolve } from "node:path";

dotenv.config({ path: resolve(__dirname, "../.env") });

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    hardhat: {},
    besu: {
      url: process.env.BESU_RPC_URL ?? "http://127.0.0.1:8545",
      chainId: 1337,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : []
    }
  }
};

export default config;