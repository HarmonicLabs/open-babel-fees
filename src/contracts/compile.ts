import { Address, ByteString, compile, Credential } from "@harmoniclabs/plu-ts";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { contract } from "./smart-wallet";
import { Script } from "@harmoniclabs/buildooor";

void async function main() {
    await mkdir("./out", { recursive: true });

    const pubKeyBytes = await readFile("./secrets/wallet.pk")

    const contractBytes = compile( contract.$( new ByteString( pubKeyBytes ) ) );

    const script = new Script("PlutusScriptV3", contractBytes);
    const stakeCreds = Address.fromString( await readFile("./secrets/mainnet-address.addr", { encoding: "utf-8" }) ).stakeCreds;

    const scriptMainnetAddress = Address.mainnet(
        Credential.script( script.hash ),
        stakeCreds
    );
    const scriptTestnetAddress = Address.testnet(
        Credential.script( script.hash ),
        stakeCreds
    );

    await Promise.all([
        writeFile("./out/smart-wallet.uplc.flat", contractBytes ),
        writeFile("./out/smart-wallet.mainnet.addr", scriptMainnetAddress.toString()),
        writeFile("./out/smart-wallet.testnet.addr", scriptTestnetAddress.toString())
    ]);

}();