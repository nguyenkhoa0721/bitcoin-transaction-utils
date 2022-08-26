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
    createSigHash(vindex: number, hashType: number): Promise<any>;
    fromHex(hex: string): void;
    deepCopy(tx: RawTransaction): void;
    genHashId(): string;
}
