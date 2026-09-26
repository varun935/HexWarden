// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract FirmwareRegistry is AccessControl {
    bytes32 public constant LAB_ROLE = keccak256("LAB_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    struct FirmwareRecord {
        bytes32 firmwareHash;
        string deviceModel;
        string version;
        address attester;
        uint256 timestamp;
        bool approved;
    }

    mapping(bytes32 => FirmwareRecord) private records;

    event FirmwareApproved(
        bytes32 indexed firmwareHash,
        string deviceModel,
        string version,
        address indexed attester,
        uint256 timestamp
    );
    event FirmwareRevoked(bytes32 indexed firmwareHash, address indexed revoker, uint256 timestamp);
    event AttesterAdded(bytes32 indexed role, address indexed account);
    event AttesterRemoved(bytes32 indexed role, address indexed account);

    constructor(address administrator) {
        _grantRole(DEFAULT_ADMIN_ROLE, administrator);
        _grantRole(GOVERNANCE_ROLE, administrator);
        _grantRole(LAB_ROLE, administrator);
        _grantRole(REVOKER_ROLE, administrator);
    }

    function approveFirmware(
        bytes32 firmwareHash,
        string calldata deviceModel,
        string calldata version
    ) external onlyRole(LAB_ROLE) {
        records[firmwareHash] = FirmwareRecord({
            firmwareHash: firmwareHash,
            deviceModel: deviceModel,
            version: version,
            attester: msg.sender,
            timestamp: block.timestamp,
            approved: true
        });
        emit FirmwareApproved(firmwareHash, deviceModel, version, msg.sender, block.timestamp);
    }

    function revokeFirmware(bytes32 firmwareHash) external onlyRole(REVOKER_ROLE) {
        require(records[firmwareHash].timestamp != 0, "unknown firmware");
        records[firmwareHash].approved = false;
        emit FirmwareRevoked(firmwareHash, msg.sender, block.timestamp);
    }

    function isApproved(bytes32 firmwareHash, string calldata deviceModel)
        external
        view
        returns (bool)
    {
        FirmwareRecord storage record = records[firmwareHash];
        return record.approved && keccak256(bytes(record.deviceModel)) == keccak256(bytes(deviceModel));
    }

    function getFirmware(bytes32 firmwareHash) external view returns (FirmwareRecord memory) {
        return records[firmwareHash];
    }

    function addAttester(bytes32 role, address account) external onlyRole(GOVERNANCE_ROLE) {
        require(role == LAB_ROLE || role == REVOKER_ROLE, "unsupported role");
        _grantRole(role, account);
        emit AttesterAdded(role, account);
    }

    function removeAttester(bytes32 role, address account) external onlyRole(GOVERNANCE_ROLE) {
        require(role == LAB_ROLE || role == REVOKER_ROLE, "unsupported role");
        _revokeRole(role, account);
        emit AttesterRemoved(role, account);
    }
}