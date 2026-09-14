// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IOpcodeLib
/// @notice Interface matching `OpcodeLib.yul`'s dispatcher, one function per
///         EIP-8141/8250/8272/7906 frame-transaction opcode.
interface IOpcodeLib {
    function approve(uint256 length, uint8 scope) external;

    function txParam(uint256 param) external returns (uint256);

    function frameDataLoad(uint256 offset, uint256 frameIndex) external returns (uint256);

    function frameDataCopy(uint256 dataOffset, uint256 length, uint256 frameIndex) external returns (bytes memory);

    function frameParam(uint256 frameIndex, uint256 param) external returns (uint256);

    function sigParam(uint256 signatureIndex, uint256 param) external returns (uint256);

    function recentRootRefLoad(uint256 field, uint256 index) external returns (uint256);

    function txTrace(uint256 in2, uint256 param) external returns (uint256);

    function eventDataCopy(uint256 eventIndex, uint256 dataOffset, uint256 length) external returns (bytes memory);

    function txDiff(uint256 param, uint256 addr, uint256 in3) external returns (uint256);

    function sigDataCopy(uint256 dataOffset, uint256 length, uint256 signatureIndex) external returns (bytes memory);

    function slotNumber() external returns (uint256);
}
