// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {GasTank} from "../src/GasTank.sol";
import {DeployOpcodeLibScript} from "./DeployOpcodeLib.s.sol";

/// @notice Deploys OpcodeLib + a fresh GasTank.
/// Usage:
///   forge script script/DeployGasTank.s.sol --rpc-url $RPC_URL \
///     --private-key $PRIVATE_KEY --broadcast
contract DeployGasTankScript is Script {
    function run() external {
        address opcodeLib = new DeployOpcodeLibScript().run();

        vm.startBroadcast();

        GasTank gasTank = new GasTank(opcodeLib);

        vm.stopBroadcast();

        console.log("gasTank:", address(gasTank));
    }
}
