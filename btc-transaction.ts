import BN from 'bn.js';
import { off } from 'process';
import secp256k1 from 'secp256k1';

import {
    readUInt64,
    p2pkhScriptSig,
    p2pkhScript,
    fromBase58Check,
    encodeSig,
    sha256,
    hash160,
} from './btc-script';

function revertTx(txByteRevertedHex: string) {
    const bytes = txByteRevertedHex.length / 2;
    const txArr = [];

    for (let i = 0; i < bytes; i++) {
        txArr.push(txByteRevertedHex.substr(i * 2, 2));
    }

    return txArr.reverse().join('');
}
export class RawTransaction {
    _tx: any;
    constructor(txType: string = 'p2pkh') {
        if (txType == 'p2pkh') {
            this._tx = { version: 2, locktime: 0, vins: [], vouts: [] };
        }
    }
    addInput(address: any, txid: any, vout: any) {
        this._tx.vins.push({
            txid,
            vout,
            hash: new Buffer(txid, 'hex').reverse().toString('hex'),
            sequence: 0xffffffff,
            script: p2pkhScript(fromBase58Check(address).hash).toString('hex'),
            address,
            scriptSig: '',
        });
    }
    addOutput(address: any, amount: any) {
        this._tx.vouts.push({
            address,
            script: p2pkhScript(fromBase58Check(address).hash).toString('hex'),
            value: amount,
        });
    }
    toJSON() {
        return JSON.parse(JSON.stringify(this._tx));
    }
    fromHex(hex: string) {
        let buffer = Buffer.from(hex, 'hex');

        let offset = 0;

        this._tx.version = buffer.readUInt32LE(offset);
        offset += 4;

        const numberOfVins = Buffer.concat([buffer.slice(offset, offset + 1)], 4).readUInt16LE(0);
        offset += 1;
        for (let i = 0; i < numberOfVins; i++) {
            const hexHash = buffer.slice(offset, offset + 32);
            const hexTxid = new Buffer(hexHash.length);
            hexHash.copy(hexTxid);
            const txid = hexTxid.reverse().toString('hex');
            const hash = hexHash.toString('hex');
            offset += 32;

            const vout = buffer.readUInt32LE(offset);
            offset += 4;

            const scriptSigLen = Buffer.concat([buffer.slice(offset, offset + 1)], 4).readUInt16LE(
                0
            );
            offset += 1;

            const scriptSig = buffer.slice(offset, offset + scriptSigLen).toString('hex');
            // const scriptSig = '';
            offset += scriptSigLen;

            const sequence = buffer.readUInt32LE(offset);
            offset += 4;

            this._tx.vins.push({
                txid,
                hash,
                vout,
                scriptSig,
                sequence,
            });
        }

        const numberOfVouts = Buffer.concat([buffer.slice(offset, offset + 1)], 4).readUInt16LE(0);
        offset += 1;
        for (let i = 0; i < numberOfVouts; i++) {
            const value = readUInt64(buffer, offset);
            offset += 8;

            const scriptLen = Buffer.concat([buffer.slice(offset, offset + 1)], 4).readUInt16LE(0);
            offset += 1;

            const script = buffer.slice(offset, offset + scriptLen).toString('hex');
            offset += scriptLen;

            this._tx.vouts.push({
                value,
                script,
            });
        }

        this._tx.locktime = buffer.readUInt16LE(offset);
        offset += 4;
    }
    toHex(): string {
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
        let txHex = Buffer.from(await this.toHex(), 'hex');
        let txHexHash = Buffer.alloc(txHex.length + 4, txHex);
        txHexHash.writeUInt32LE(hashType, txHexHash.length - 4);
        return sha256(sha256(txHexHash));
    }
    deepCopy(tx: RawTransaction) {
        this._tx = JSON.parse(JSON.stringify(tx._tx));
    }
    genHashId(): string {
        const tx = new RawTransaction();
        tx.deepCopy(this);
        for (let i in tx._tx.vins) {
            tx._tx.vins[i].scriptSig = '';
        }

        const hash = hash160(tx.toHex());
        return hash.toString('hex');
    }
}

// async function test() {
//     let tx = new RawTransaction('p2pkh');
//     tx.addInput(
//         'n2UeDaa2pztrvYaBh5kEmc6bGwKM5CufL6',
//         '59505b56fa2602d58c4d50bf80db2ab94152b96c4892ead79c6a2e0d3ad5d0a4',
//         0
//     );
//     tx.addOutput('n2UeDaa2pztrvYaBh5kEmc6bGwKM5CufL6', '30000');
//     await tx.sign('472778e9ff4521c485de10c739d32e760952c19d4669ac7128cc23feca28f4f4');
//     console.log(tx.toHex());

//     let tx1 = new RawTransaction('p2pkh');
//     tx1.fromhex(
//         '0200000001a4d0d53a0d2e6a9cd7ea92486cb95241b92adb80bf504d8cd50226fa565b5059000000008a473044022017c28c75b2e3fc0370fc44554ab475ed9edca473112a7fed2cd58cf17595054102207ed7ff11e417a1994428832692fd1eae2b498921d80f1aaa4fe52b7407232f3a014104633f9eb94b0e4fda4e78fd0e6e021270ad75329b8b2a35c9ee61cad2a3df9bc2d9fe0907eb260bda7a1fe44171ea0da297e03ca8b5a680c245af50d0a08ee0a7ffffffff0130750000000000001976a914e5eab830d1416b52358351f5a30c80d3f91ab12b88ac00000000'
//     );
//     console.log(tx.genHashId());
//     console.log(tx1.genHashId());
//     console.log(tx1.toJSON());
// }

// test();

