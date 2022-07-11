import BN from 'bn.js';
import secp256k1 from 'secp256k1';

import { p2pkhScriptSig, p2pkhScript, fromBase58Check, encodeSig, sha256 } from './btc-script';

export class Transaction {
    _tx: any;
    constructor(txType: string = 'p2pkh') {
        if (txType == 'p2pkh') {
            this._tx = { version: 2, locktime: 0, vins: [], vouts: [] };
        }
    }
    addInput(txid: any, vout: any, address: any) {
        this._tx.vins.push({
            txid,
            vout,
            hash: new Buffer(txid, 'hex').reverse().toString('hex'),
            sequence: 0xffffffff,
            script: p2pkhScript(fromBase58Check(address).hash).toString('hex'),
            scriptSig: '',
        });
    }
    addOutput(address: any, amount: any) {
        this._tx.vouts.push({
            script: p2pkhScript(fromBase58Check(address).hash).toString('hex'),
            value: amount,
        });
    }
    toJSON() {
        return this._tx;
    }
    async toHex(): Promise<any> {
        let buffer = Buffer.alloc(1000);
        let offset = 0;
        //version
        buffer.writeUInt32LE(this._tx.version, offset);
        offset += 4;
        //vin len
        buffer.writeUInt16LE(this._tx.vins.length, offset);
        offset += 1;
        for (let i in this._tx.vins) {
            let input = this._tx.vins[i];
            //txid
            buffer.write(input.hash, offset, 32, 'hex');
            offset += 32;
            //vout
            buffer.writeUInt32LE(input.vout, offset);
            offset += 4;
            //script len & script
            buffer.writeUInt16LE(input.scriptSig.length / 2, offset);
            offset += 1;
            if (input.scriptSig.length > 0) {
                buffer.write(input.scriptSig, offset, input.scriptSig.length / 2, 'hex');
                offset += input.scriptSig.length / 2;
            }

            buffer.writeUInt32LE(input.sequence, offset);
            offset += 4;
        }
        //vout len
        buffer.writeUInt16LE(this._tx.vouts.length, offset);
        offset += 1;
        for (let i in this._tx.vouts) {
            let output = this._tx.vouts[i];
            //amount
            let BNValue = new BN(output.value);
            buffer.write(BNValue.toBuffer('le', 8).toString('hex'), offset, 8, 'hex');
            offset += 8;
            //script len & script
            buffer.writeUInt16LE(output.script.length / 2, offset);
            offset += 1;
            buffer.write(output.script, offset, output.script.length / 2, 'hex');
            offset += output.script.length / 2;
        }
        //locktime
        buffer.writeUInt16LE(this._tx.locktime, offset);
        offset += 4;

        if (offset < buffer.length) {
            buffer = buffer.slice(0, offset);
        }

        return buffer.toString('hex');
    }
    async sign(privKey: any): Promise<any> {
        privKey = Uint8Array.from(Buffer.from(privKey, 'hex'));
        let pubKey = secp256k1.publicKeyCreate(privKey, false);
        for (let i = 0; i < this._tx.vins.length; i++) {
            let sigHash = await this.createSigHash(i, 1);
            let sig = secp256k1.ecdsaSign(sigHash, privKey);
            let encSig = encodeSig(Buffer.from(sig.signature), 1);

            this._tx.vins[i].script = p2pkhScriptSig(encSig, Buffer.from(pubKey)).toString('hex');
        }
        for (let i = 0; i < this._tx.vins.length; i++) {
            this._tx.vins[i].scriptSig = this._tx.vins[i].script;
        }
    }
    async createSigHash(vindex: number, hashType: number): Promise<any> {
        for (let i = 0; i < this._tx.vins.length; i++) {
            if (i == vindex) this._tx.vins[i].scriptSig = this._tx.vins[i].script;
            else this._tx.vins[i].scriptSig = '';
        }
        let txHex = Buffer.from(await this.toHex(), 'hex'); //bug
        let txHexHash = Buffer.alloc(txHex.length + 4, txHex);
        txHexHash.writeUInt32LE(hashType, txHexHash.length - 4);
        return sha256(sha256(txHexHash));
    }
}

async function test() {
    let tx = new Transaction('p2pkh');
    tx.addInput(
        '59505b56fa2602d58c4d50bf80db2ab94152b96c4892ead79c6a2e0d3ad5d0a4',
        0,
        'n2UeDaa2pztrvYaBh5kEmc6bGwKM5CufL6'
    );
    tx.addOutput('n2UeDaa2pztrvYaBh5kEmc6bGwKM5CufL6', '30000');
    await tx.sign('#PrivateKey');
    console.log(await tx.toHex());
}

test();
