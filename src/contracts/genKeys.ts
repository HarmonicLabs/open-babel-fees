import { Address, Credential, PrivateKey } from "@harmoniclabs/buildooor";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

void async function main() {

    await mkdir("./secrets", { recursive: true });

    if( existsSync("./secrets/wallet.sk") )
    throw new Error("secret key already exists at ./secrets/wallet.sk, if you **really** want to override it, remove it before running this script again");

    const keyBytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const sk = new PrivateKey( keyBytes );
    const pk = sk.derivePublicKey();
    const pkh = pk.hash;

    const stakeCreds = typeof process.env.ADDRESS === "string" ?
        Address.fromString( process.env.ADDRESS ).stakeCreds :
        undefined; 

    const testAddress = Address.testnet(
        Credential.keyHash( pkh ),
        stakeCreds
    );
    const mainnetAddress = Address.mainnet(
        Credential.keyHash( pkh ),
        stakeCreds
    );

    await Promise.all([
        writeFile("./secrets/wallet.sk", sk.toBuffer()),
        writeFile("./secrets/wallet.pk", pk.toBuffer()),
        writeFile("./secrets/wallet.pkh", pkh.toBuffer()),
        writeFile("./secrets/testnet-address.addr", testAddress.toString()),
        writeFile("./secrets/mainnet-address.addr", mainnetAddress.toString())
    ]);
    
}();