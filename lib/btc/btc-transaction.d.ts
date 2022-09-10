/// <reference types="node" />
export declare class RawTransaction {
    _tx: any;
    _isSegwit: boolean;
    constructor(isSegwit?: boolean);
    addInput(address: string, txid: string, vout: number, amount?: string): void;
    addOutput(address: string, amount: string): void;
    toJSON(): any;
    toHex(): string;
    toSignHex(vindex: number): string;
    toSegwitSignHex(vindex: number): string;
    sign(privKey: any, inputs: number[]): Promise<any>;
    createSigHash(vindex: number, hashType: number, redeemScript?: Buffer): Promise<any>;
    fromHex(hex: string): void;
    deepCopy(tx: RawTransaction): void;
    genHashId(): string;
}
export declare class MultiSigTransaction extends RawTransaction {
    _pubKeys: Array<Buffer>;
    _n: number;
    _m: number;
    constructor(n: number, m: number, pubKeys: Array<string>, isSegwit?: boolean);
    addMultiSigInput(address: string, txid: string, vout: number, signatures: Array<string>, amount?: string): void;
    sign(privKey: any, inputs: number[]): Promise<any>;
    multiSigScriptSig(sigs: Array<string>): Buffer;
    generateRedeemScript(): Buffer;
}
