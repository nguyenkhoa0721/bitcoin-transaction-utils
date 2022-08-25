import * as crypto from 'crypto';
import bs58check from 'bs58check';
import { bech32 } from 'bech32';
import OPS from './btc-ops-mapping';
import BN from 'bn.js';
let bip66 = require('bip66');

function hash160(data: any) {
    return ripemd160(sha256(data));
}
function sha256(data: any) {
    let hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest();
}
function ripemd160(data: any) {
    let hash = crypto.createHash('ripemd160');
    hash.update(data);
    return hash.digest();
}
function binaryStringToBuffer(binary: string) {
    const groups = binary.match(/[01]{8}/g);
    let numbers: number[] = [];
    if (groups) numbers = groups.map((binary) => parseInt(binary, 2));
    return Buffer.from(new Uint8Array(numbers).buffer);
}

function fromBase58Check(address: string) {
    let payload = bs58check.decode(address);
    let version = payload.readUInt8(0);
    let hash = payload.slice(1);
    return { version, hash };
}
function bach32Decode(address: string) {
    let words = bech32.decode(address).words;
    words = words.slice(1);

    let bin = '';
    for (let i in words) {
        const tmp = words[i].toString(2);
        bin += '0'.repeat(5 - tmp.length) + tmp;
    }
    const buf = Buffer.from(bin, 'binary');
    return binaryStringToBuffer(bin);
}

// @description: With var has type buffer, func will add length of buffer before
function compileScript(chunks: any[]) {
    let bufferSize = 0;
    for (let i in chunks) {
        if (typeof chunks[i] === 'number') {
            bufferSize += 1;
        } else {
            bufferSize += chunks[i].length + 1;
        }
    }
    let buffer = Buffer.alloc(bufferSize);
    let offset = 0;
    for (let chunk of chunks) {
        if (chunk instanceof Buffer) {
            buffer.writeUInt16LE(chunk.length, offset);
            offset += 1;
            chunk.copy(buffer, offset);
            offset += chunk.length;
        } else {
            new Buffer(chunk.toString(16), 'hex').copy(buffer, offset);
            offset += 1;
        }
    }
    return buffer;
}

// @description:   This func will add scriptSig len in vin and script len in vout
//                 writeUInt<XX>LE is used for converting number in dex to hex and writing to buffer with little endian
//                 Value in vout -> convert to BN -> Buffer LE -> String(hex) -> Write to buffer

function encodeSig(signature: any, hashType: any) {
    const hashTypeMod = hashType & ~0x80;
    if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error('Invalid hashType ' + hashType);

    const hashTypeBuffer = Buffer.from([hashType]);

    const r = toDER(signature.slice(0, 32));
    const s = toDER(signature.slice(32, 64));

    return Buffer.concat([bip66.encode(r, s), hashTypeBuffer]);
}

function toDER(x: any) {
    let i = 0;
    while (x[i] === 0) ++i;
    if (i === x.length) return Buffer.alloc(1);
    x = x.slice(i);
    if (x[0] & 0x80) return Buffer.concat([Buffer.alloc(1), x], 1 + x.length);
    return x;
}

function readUInt64(buff: Buffer, offset: number) {
    var word0 = buff.readUInt32LE(offset);
    var word1 = buff.readUInt32LE(offset + 4);
    return new BN(word0).add(new BN(word1).mul(new BN(100000000))).toString(10);
}

function p2pkhScript(hash160PubKey: Buffer) {
    return compileScript([
        OPS.OP_DUP,
        OPS.OP_HASH160,
        hash160PubKey,
        OPS.OP_EQUALVERIFY,
        OPS.OP_CHECKSIG,
    ]);
}

function p2shScript(hash160Script: Buffer) {
    return compileScript([OPS.OP_HASH160, hash160Script, OPS.OP_EQUAL]);
}

function p2wpkhScript(hash160PubKey: Buffer) {
    return compileScript([OPS.OP_0, hash160PubKey]);
}

function p2wshScript(hash160PubKey: Buffer) {
    //@Todo: generate hash160Script
    return compileScript([OPS.OP_0, hash160PubKey]);
}

function generateScript(type: string, address: string) {
    let hash160PubKey: Buffer;
    switch (type) {
        case 'p2pkh':
            hash160PubKey = fromBase58Check(address).hash;
            return p2pkhScript(hash160PubKey);
        case 'p2sh':
            hash160PubKey = fromBase58Check(address).hash;
            return p2shScript(hash160PubKey);
        case 'p2wpkh':
            hash160PubKey = bach32Decode(address);
            return p2wpkhScript(hash160PubKey);
        case 'p2wsh':
            hash160PubKey = Buffer.alloc(0);
            return p2wshScript(hash160PubKey);
        default:
            throw new Error('Unsupported script type');
    }
}

function p2pkhScriptSig(sig: any, pubKey: any) {
    return compileScript([sig, pubKey]);
}

function p2shScriptSig(sig: any, pubKey: any) {
    return compileScript([OPS.OP_0, sig, pubKey]);
}

function p2wpkhScriptSig(sig: any, pubKey: any) {
    return compileScript([pubKey, sig]);
}

function p2wshScriptSig(sig: any, pubKey: any) {
    return compileScript([pubKey, sig]);
}

export {
    OPS,
    p2pkhScriptSig,
    p2wpkhScriptSig,
    fromBase58Check,
    encodeSig,
    sha256,
    ripemd160,
    compileScript,
    hash160,
    readUInt64,
    generateScript,
    bach32Decode,
    p2pkhScript,
};
