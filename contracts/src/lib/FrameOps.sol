// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IOpcodeLib} from "../interfaces/IOpcodeLib.sol";

/// @title FrameOps
/// @notice Solidity wrappers around `OpcodeLib`'s raw delegatecall-based opcode calls.
library FrameOps {
    address internal constant RECENT_ROOT_ADDRESS = 0x0000000000000000000000000000000000008272;

    enum Scope {
        None,
        Payment,
        Execution,
        ExecutionAndPayment
    }

    /// Declares the transaction authorised for `scope`, returning no data.
    function approve(address opcodeLib, Scope scope) internal {
        bytes memory outputData;
        _call(
            opcodeLib,
            abi.encodePacked(
                abi.encodeWithSelector(IOpcodeLib.approve.selector, outputData.length, uint8(scope)), outputData
            )
        );
    }

    /// Declares the transaction authorised for `scope`, returning
    /// `outputData` as the frame's return data.
    function approve(address opcodeLib, bytes memory outputData, Scope scope) internal {
        _call(
            opcodeLib,
            abi.encodePacked(
                abi.encodeWithSelector(IOpcodeLib.approve.selector, outputData.length, uint8(scope)), outputData
            )
        );
    }

    /// Reads a field of the transaction envelope.
    function txParam(address opcodeLib, uint256 param) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.txParam, (param))), (uint256));
    }

    /// Reads a word of the current frame's data.
    function frameDataLoad(address opcodeLib, uint256 offset, uint256 frameIndex) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.frameDataLoad, (offset, frameIndex))), (uint256));
    }

    /// Reads a range of the current frame's data.
    function frameDataCopy(address opcodeLib, uint256 dataOffset, uint256 length, uint256 frameIndex)
        internal
        returns (bytes memory)
    {
        return _call(opcodeLib, abi.encodeCall(IOpcodeLib.frameDataCopy, (dataOffset, length, frameIndex)));
    }

    /// Reads a field of a frame.
    function frameParam(address opcodeLib, uint256 frameIndex, uint256 param) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.frameParam, (frameIndex, param))), (uint256));
    }

    /// Reads metadata about a supplied signature. `param` must be 0-3 — use
    /// `sigDataCopy` to read an ARBITRARY signature's raw bytes instead.
    function sigParam(address opcodeLib, uint256 signatureIndex, uint256 param) internal returns (uint256) {
        require(param != 4, "FrameOps: use sigDataCopy for param==4");
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.sigParam, (signatureIndex, param))), (uint256));
    }

    /// Reads a recent-root reference from the transaction envelope.
    function recentRootRefLoad(address opcodeLib, uint256 field, uint256 index) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.recentRootRefLoad, (field, index))), (uint256));
    }

    /// Publishes `root` under `salt` as a recent root.
    function publishRecentRoot(bytes32 salt, bytes32 root) internal {
        (bool ok,) = RECENT_ROOT_ADDRESS.call(abi.encodePacked(salt, root));
        require(ok, "FrameOps: recent root publish failed");
    }

    /// Reads gas context and execution facts. POST_TX frames only.
    function txTrace(address opcodeLib, uint256 in2, uint256 param) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.txTrace, (in2, param))), (uint256));
    }

    /// Reads events the transaction emitted. POST_TX frames only.
    function eventDataCopy(address opcodeLib, uint256 eventIndex, uint256 dataOffset, uint256 length)
        internal
        returns (bytes memory)
    {
        return _call(opcodeLib, abi.encodeCall(IOpcodeLib.eventDataCopy, (eventIndex, dataOffset, length)));
    }

    /// Reads the state changes the transaction made to `addr`. POST_TX frames only.
    function txDiff(address opcodeLib, uint256 param, uint256 addr, uint256 in3) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.txDiff, (param, addr, in3))), (uint256));
    }

    /// Reads an ARBITRARY-scheme signature's raw bytes.
    function sigDataCopy(address opcodeLib, uint256 dataOffset, uint256 length, uint256 signatureIndex)
        internal
        returns (bytes memory)
    {
        return _call(opcodeLib, abi.encodeCall(IOpcodeLib.sigDataCopy, (dataOffset, length, signatureIndex)));
    }

    /// Reads the current block's slot number (EIP-7843 SLOTNUM).
    function slotNumber(address opcodeLib) internal returns (uint256) {
        return abi.decode(_call(opcodeLib, abi.encodeCall(IOpcodeLib.slotNumber, ())), (uint256));
    }

    function _call(address opcodeLib, bytes memory data) private returns (bytes memory) {
        (bool ok, bytes memory ret) = opcodeLib.delegatecall(data);
        require(ok, "FrameOps: opcode call failed");
        return ret;
    }
}
