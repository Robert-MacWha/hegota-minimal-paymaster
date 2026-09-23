/// @title OpcodeLib
/// @notice Exposes the EIP-8141/8250/8272/7906 frame-transaction opcodes as
///         ABI-callable functions, via `verbatim` — an encoding only a
///         standalone Yul object can emit, not regular Solidity or inline
///         assembly.
/// @dev Reached via DELEGATECALL, not CALL/STATICCALL: APPROVE requires the
///      executing call frame's `to` to equal the enclosing frame
///      transaction's declared target. DELEGATECALL preserves the caller's
///      own `to`; a plain CALL would make APPROVE see `to == OpcodeLib`
///      itself and fail. Every case below is a pure passthrough: read fixed
///      words off calldata, forward them to `verbatim`, return the raw
///      result — for the cases that copy raw bytes (`approve` and the
///      `*Copy` opcodes), the copy's memory offset is always 0 since
///      DELEGATECALL gives OpcodeLib its own fresh memory. Any higher-level
///      handling (ABI encoding, enums, argument validation) lives in
///      `FrameOps.sol`.
object "OpcodeLib" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            if lt(calldatasize(), 4) { revert(0, 0) }
            let selector := shr(224, calldataload(0))

            switch selector

            // approve(uint256,uint8) -> 0x3eabe96f. APPROVE (0xAA).
            // Stack: [offset, length, scope]. Calldata: length, scope, then
            // `length` raw output bytes (see FrameOps.approve).
            case 0x3eabe96f {
                let length := calldataload(4)
                let scope := calldataload(36)
                calldatacopy(0, 68, length)
                verbatim_3i_0o(hex"AA", 0, length, scope)
                stop()
            }

            // txParam(uint256) -> 0x16525c7f. TXPARAM (0xB0). Stack: [param].
            case 0x16525c7f {
                let param := calldataload(4)
                let value := verbatim_1i_1o(hex"B0", param)
                mstore(0, value)
                return(0, 32)
            }

            // frameDataLoad(uint256,uint256) -> 0x7129a8fe. FRAMEDATALOAD (0xB1). Stack: [offset, frameIndex].
            case 0x7129a8fe {
                let offset := calldataload(4)
                let frameIndex := calldataload(36)
                let value := verbatim_2i_1o(hex"B1", offset, frameIndex)
                mstore(0, value)
                return(0, 32)
            }

            // frameDataCopy(uint256,uint256,uint256) -> 0x03f2f011. FRAMEDATACOPY (0xB2). Stack: [memOffset, dataOffset, length, frameIndex].
            case 0x03f2f011 {
                let dataOffset := calldataload(4)
                let length := calldataload(36)
                let frameIndex := calldataload(68)
                verbatim_4i_0o(hex"B2", 0, dataOffset, length, frameIndex)
                return(0, length)
            }

            // frameParam(uint256,uint256) -> 0xff846610. FRAMEPARAM (0xB3). Stack: [frameIndex, param].
            case 0xff846610 {
                let frameIndex := calldataload(4)
                let param := calldataload(36)
                let value := verbatim_2i_1o(hex"B3", frameIndex, param)
                mstore(0, value)
                return(0, 32)
            }

            // sigParam(uint256,uint256) -> 0xf457766f. SIGPARAM (0xB4) metadata form. Stack: [signatureIndex, param].
            case 0xf457766f {
                let signatureIndex := calldataload(4)
                let param := calldataload(36)
                let value := verbatim_2i_1o(hex"B4", signatureIndex, param)
                mstore(0, value)
                return(0, 32)
            }

            // txTrace(uint256,uint256) -> 0xb167be16. TXTRACE (0xB6). Stack: [in2, param]. POST_TX frames only.
            case 0xb167be16 {
                let in2 := calldataload(4)
                let param := calldataload(36)
                let value := verbatim_2i_1o(hex"B6", in2, param)
                mstore(0, value)
                return(0, 32)
            }

            // eventDataCopy(uint256,uint256,uint256) -> 0x9666f50f. EVENTDATACOPY (0xB7). Stack: [eventIndex, memOffset, dataOffset, length]. POST_TX frames only.
            case 0x9666f50f {
                let eventIndex := calldataload(4)
                let dataOffset := calldataload(36)
                let length := calldataload(68)
                verbatim_4i_0o(hex"B7", eventIndex, 0, dataOffset, length)
                return(0, length)
            }

            // txDiff(uint256,uint256,uint256) -> 0x91a28001. TXDIFF (0xB8). Stack: [param, address, in3]. POST_TX frames only.
            case 0x91a28001 {
                let param := calldataload(4)
                let addr := calldataload(36)
                let in3 := calldataload(68)
                let value := verbatim_3i_1o(hex"B8", param, addr, in3)
                mstore(0, value)
                return(0, 32)
            }

            // sigDataCopy(uint256,uint256,uint256) -> 0x9b547936. SIGDATACOPY (0xB5). Stack: [memOffset, dataOffset, length, signatureIndex]. ARBITRARY-scheme signatures only.
            case 0x9b547936 {
                let dataOffset := calldataload(4)
                let length := calldataload(36)
                let signatureIndex := calldataload(68)
                verbatim_4i_0o(hex"B5", 0, dataOffset, length, signatureIndex)
                return(0, length)
            }

            // slotNumber() -> 0x37cda272. SLOTNUM (0x4B). Stack: [].
            case 0x37cda272 {
                let value := verbatim_0i_1o(hex"4B")
                mstore(0, value)
                return(0, 32)
            }

            default { revert(0, 0) }
        }
    }
}
