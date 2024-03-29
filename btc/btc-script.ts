import * as crypto from 'crypto';
import CryptoJS from 'crypto-js';
import { SHA256, RIPEMD160 } from 'crypto-js';
import bs58check from 'bs58check';
import { bech32 } from 'bech32';
import OPS from './btc-ops-mapping';
import BN from 'bn.js';
import OP_CODE from './btc-ops-mapping';
let bip66 = require('bip66');

function WordArrayToBuffer(wordArray: CryptoJS.lib.WordArray): Buffer {
    const u8Array = new Uint8Array(wordArray.sigBytes);
    for (let i = 0x0; i < wordArray.sigBytes; i++) {
        u8Array[i] = (wordArray.words[i >>> 0x2] >>> (0x18 - (i % 0x4) * 0x8)) & 0xff;
    }
    return new Buffer(new Uint8Array(u8Array).buffer);
}
function BufferToWordArray(buffer: Buffer): CryptoJS.lib.WordArray {
    var wa = [],
        i: number;
    for (i = 0; i < buffer.length; i++) {
        wa[(i / 4) | 0] |= buffer[i] << (24 - 8 * i);
    }

    return CryptoJS.lib.WordArray.create(wa, buffer.length);
}
function hash160(data: any) {
    return ripemd160(sha256(data));
}

function sha256(data: any): Buffer {
    const wa = BufferToWordArray(data);
    return WordArrayToBuffer(SHA256(wa));
}
function ripemd160(data: any) {
    const wa = BufferToWordArray(data);
    return WordArrayToBuffer(RIPEMD160(wa));
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
            if (chunk.length < 0x4c) {
                buffer.writeUInt8(chunk.length, offset);
                offset += 1;
            } else if (chunk.length <= 0xff) {
                buffer.writeUInt8(OP_CODE.OP_PUSHDATA1, offset);
                offset += 1;
                buffer.writeUInt8(chunk.length, offset);
                offset += 1;
            } else if (chunk.length <= 0xffff) {
                buffer.writeUInt8(OP_CODE.OP_PUSHDATA2, offset);
                offset += 1;
                buffer.writeUInt16LE(chunk.length, offset);
                offset += 2;
            } else {
                buffer.writeUInt8(OP_CODE.OP_PUSHDATA4, offset);
                offset += 1;
                buffer.writeUInt32LE(chunk.length, offset);
                offset += 4;
            }
            chunk.copy(buffer, offset);
            offset += chunk.length;
        } else {
            //@TODO len of chunk must be 2 for react native
            let strChunk = chunk.toString(16);
            if (strChunk.length == 1) strChunk = '0' + strChunk;
            new Buffer(strChunk, 'hex').copy(buffer, offset);
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
            hash160PubKey = bach32Decode(address);
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

function vi2h(num: number): Buffer {
    let hex: Buffer = null;
    if (num < 0xfd) {
        hex = new BN(num).toBuffer('le', 1);
    } else if (num < 0xffff) {
        hex = n2h(num, 0xfd, 2);
    } else if (num < 0xffffffff) {
        hex = n2h(num, 0xfe, 4);
    }
    return hex;
}
function n2h(num: number, start: number, len: number): Buffer {
    return Buffer.concat([Buffer.from(start.toString(16), 'hex'), new BN(num).toBuffer('le', len)]);
}
function h2vi(buffer: Buffer, offset: number): [number, number] {
    let num = parseInt(buffer.subarray(0, 1).toString('hex'), 16);
    if (num < 0xfd) {
        return [num, offset + 1];
    } else if (num < 0xffff) {
        return [buffer.readUInt16LE(1), offset + 3];
    } else if (num < 0xffffffff) {
        return [buffer.readUInt32LE(1), offset + 6];
    }
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
    p2shScriptSig,
    vi2h,
    h2vi,
};
