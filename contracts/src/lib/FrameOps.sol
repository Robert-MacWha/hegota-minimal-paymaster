// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IOpcodeLib} from "../interfaces/IOpcodeLib.sol";

/// @title FrameOps
/// @notice Solidity wrappers around `OpcodeLib`'s raw delegatecall-based opcode calls.
library FrameOps {
    address internal constant RECENT_ROOT_ADDRESS = 0x0000000000000000000000000000000000008272;

    /// EIP-8272 `RECENT_ROOT_TUPLE_BYTES`: one packed
    /// `source_id(32) || uint64_be(slot) || root(32)` reference.
    uint256 internal constant RECENT_ROOT_TUPLE_BYTES = 72;
    /// EIP-8272 `MAX_RECENT_ROOT_REFERENCES`.
    uint256 internal constant MAX_RECENT_ROOT_REFERENCES = 16;
    /// EIP-8141 `FrameMode::Verify`, as reported by `FRAMEPARAM` param `0x02`.
    uint256 internal constant VERIFY_MODE = 1;

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

    /// Reads the `(source_id, root)` of tuple `refIndex` out of the EIP-8272
    /// recent-root verifier frame at `frameIndex`.
    ///
    /// Recent roots used to live in a `recent_root_references` envelope field
    /// read by a `RECENTROOTREFLOAD` opcode; that opcode is gone (0xB5 is now
    /// SIGDATACOPY) and the roots are the data of a dedicated VERIFY frame
    /// targeting `RECENT_ROOT_ADDRESS`, packed as
    /// `source_id(32) || uint64_be(slot) || root(32)`.
    function recentRootTuple(address opcodeLib, uint256 frameIndex, uint256 refIndex)
        internal
        returns (bytes32 sourceId, bytes32 root)
    {
        _requireRecentRootVerifierFrame(opcodeLib, frameIndex, refIndex);

        uint256 offset = refIndex * RECENT_ROOT_TUPLE_BYTES;
        sourceId = bytes32(frameDataLoad(opcodeLib, offset, frameIndex));
        // `slot` occupies bytes 32..40 of the tuple, so the root is the word
        // starting 40 bytes in.
        root = bytes32(frameDataLoad(opcodeLib, offset + 40, frameIndex));
    }

    /// Requires that the frame at `frameIndex` is the protocol's recent-root
    /// verifier frame and carries a tuple at `refIndex`.
    ///
    /// @dev These are exactly the conditions of ethrex's
    ///      `Frame::is_recent_root_verifier`. A frame satisfying them is the
    ///      canonical verifier frame, which consensus (a) rejects unless it is
    ///      the transaction's first frame -- or second, behind an expiry
    ///      verifier -- and (b) checks tuple by tuple against the
    ///      `RECENT_ROOT_ADDRESS` predeploy before any frame runs. Without the
    ///      full shape check a caller could point this at some other frame
    ///      whose data it controls and hand back a forged root.
    function _requireRecentRootVerifierFrame(address opcodeLib, uint256 frameIndex, uint256 refIndex) private {
        require(
            frameParam(opcodeLib, frameIndex, 0x00) == uint256(uint160(RECENT_ROOT_ADDRESS)),
            "FrameOps: root frame target"
        );
        require(frameParam(opcodeLib, frameIndex, 0x02) == VERIFY_MODE, "FrameOps: root frame not VERIFY");
        require(frameParam(opcodeLib, frameIndex, 0x03) == 0, "FrameOps: root frame flags");
        require(frameParam(opcodeLib, frameIndex, 0x08) == 0, "FrameOps: root frame value");
        require(frameParam(opcodeLib, frameIndex, 0x09) == 0, "FrameOps: root frame state gas");

        uint256 length = frameParam(opcodeLib, frameIndex, 0x04);
        uint256 count = length / RECENT_ROOT_TUPLE_BYTES;
        require(
            length % RECENT_ROOT_TUPLE_BYTES == 0 && count != 0 && count <= MAX_RECENT_ROOT_REFERENCES,
            "FrameOps: root frame data"
        );
        require(refIndex < count, "FrameOps: root ref index");
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
