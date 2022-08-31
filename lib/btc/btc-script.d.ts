/// <reference types="node" />
import OPS from './btc-ops-mapping';
declare function hash160(data: any): Buffer;
declare function sha256(data: any): Buffer;
declare function ripemd160(data: any): Buffer;
declare function fromBase58Check(address: string): {
    version: number;
    hash: Buffer;
};
declare function bach32Decode(address: string): Buffer;
declare function compileScript(chunks: any[]): Buffer;
declare function encodeSig(signature: any, hashType: any): Buffer;
declare function readUInt64(buff: Buffer, offset: number): string;
declare function p2pkhScript(hash160PubKey: Buffer): Buffer;
declare function generateScript(type: string, address: string): Buffer;
declare function p2pkhScriptSig(sig: any, pubKey: any): Buffer;
declare function p2shScriptSig(sig: any, pubKey: any): Buffer;
declare function p2wpkhScriptSig(sig: any, pubKey: any): Buffer;
declare function vi2h(num: number): Buffer;
declare function h2vi(buffer: Buffer, offset: number): [number, number];
export { OPS, p2pkhScriptSig, p2wpkhScriptSig, fromBase58Check, encodeSig, sha256, ripemd160, compileScript, hash160, readUInt64, generateScript, bach32Decode, p2pkhScript, p2shScriptSig, vi2h, h2vi, };
