import { expect } from "chai";
import { ethers } from "hardhat";
import type { FirmwareRegistry } from "../typechain-types/contracts/FirmwareRegistry";

describe("FirmwareRegistry", function () {
  async function fixture(): Promise<{
    registry: FirmwareRegistry;
    governance: Awaited<ReturnType<typeof ethers.getSigners>>[number];
    lab: Awaited<ReturnType<typeof ethers.getSigners>>[number];
    revoker: Awaited<ReturnType<typeof ethers.getSigners>>[number];
    stranger: Awaited<ReturnType<typeof ethers.getSigners>>[number];
  }> {
    const [governance, lab, revoker, stranger] = await ethers.getSigners();
    const registry = (await ethers.deployContract("FirmwareRegistry", [governance.address])) as unknown as FirmwareRegistry;
    await registry.addAttester(await registry.LAB_ROLE(), lab.address);
    await registry.addAttester(await registry.REVOKER_ROLE(), revoker.address);
    return { registry, governance, lab, revoker, stranger };
  }

  it("approves and looks up firmware", async function () {
    const { registry, lab } = await fixture();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("clean"));
    await expect(registry.connect(lab).approveFirmware(hash, "ESP32-X", "2.1"))
      .to.emit(registry, "FirmwareApproved");
    expect(await registry.isApproved(hash, "ESP32-X")).to.equal(true);
    expect(await registry.isApproved(hash, "Other")).to.equal(false);
  });

  it("rejects unauthorized approval and revocation", async function () {
    const { registry, stranger } = await fixture();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("clean"));
    await expect(registry.connect(stranger).approveFirmware(hash, "ESP32-X", "2.1"))
      .to.be.reverted;
    await expect(registry.connect(stranger).revokeFirmware(hash)).to.be.reverted;
  });

  it("preserves a record while revoking approval", async function () {
    const { registry, lab, revoker } = await fixture();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("clean"));
    await registry.connect(lab).approveFirmware(hash, "ESP32-X", "2.1");
    await expect(registry.connect(revoker).revokeFirmware(hash)).to.emit(registry, "FirmwareRevoked");
    const record = await registry.getFirmware(hash);
    expect(record.firmwareHash).to.equal(hash);
    expect(record.version).to.equal("2.1");
    expect(record.approved).to.equal(false);
    expect(await registry.isApproved(hash, "ESP32-X")).to.equal(false);
  });

  it("lets governance manage roles", async function () {
    const { registry, governance, stranger } = await fixture();
    const labRole = await registry.LAB_ROLE();
    await registry.connect(governance).addAttester(labRole, stranger.address);
    expect(await registry.hasRole(labRole, stranger.address)).to.equal(true);
    await registry.connect(governance).removeAttester(labRole, stranger.address);
    expect(await registry.hasRole(labRole, stranger.address)).to.equal(false);
  });

  it("returns an empty record for an unknown hash", async function () {
    const { registry } = await fixture();
    const record = await registry.getFirmware(ethers.ZeroHash);
    expect(record.timestamp).to.equal(0);
    expect(await registry.isApproved(ethers.ZeroHash, "ESP32-X")).to.equal(false);
  });
});