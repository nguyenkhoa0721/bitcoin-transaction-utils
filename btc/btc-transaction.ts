import BN from 'bn.js';
import secp256k1 from 'secp256k1';
import OPS from './btc-ops-mapping';
import {
    readUInt64,
    p2pkhScriptSig,
    p2wpkhScriptSig,
    fromBase58Check,
    encodeSig,
    sha256,
    hash160,
    generateScript,
    bach32Decode,
    p2pkhScript,
    compileScript,
    p2shScriptSig,
    vi2h,
    h2vi,
} from './btc-script';

import { checkAddressType } from './btc-address-type';
import { off } from 'process';
export class RawTransaction {
    _tx: any;
    _isSegwit: boolean = true;
    constructor(isSegwit: boolean = true) {
        this._isSegwit = isSegwit;
        if (!this._isSegwit) {
            this._tx = { version: 2, locktime: 0, vins: [], vouts: [] };
        } else if (this._isSegwit) {
            this._tx = { version: 2, flag: 1, locktime: 0, vins: [], vouts: [] };
        } else {
            throw new Error('Transaction type is not supported');
        }
    }
    /*
    @param  
        {string} address - The address to send to.
        {number} amount - The amount to send.
        {string} txid - The transaction id of the previous transaction.
    @description 
        Adds a vin to the transaction.
    */
    addInput(address: string, txid: string, vout: number, amount: string = '0') {
        const addressType = checkAddressType(address);
        const hash = new Buffer(txid, 'hex').reverse().toString('hex');
        const script = generateScript(addressType, address).toString('hex');

        this._tx.vins.push({
            txid,
            vout,
            hash,
            sequence: 0xffffffff,
            script,
            address,
            value: amount,
            scriptSig: '',
            addressType,
            witness: '',
        });
    }
    /*
    @param
        {string} address - The address to send to.
        {number} amount - The amount to send.
    @description
        Adds a vout to the transaction.
    */
    addOutput(address: string, amount: string) {
        const addressType = checkAddressType(address);
        const script = generateScript(addressType, address).toString('hex');

        this._tx.vouts.push({
            address,
            script,
            value: amount,
            addressType,
        });
    }
    /*
    @description
        Returns the transaction in JSON format.
    */
    toJSON() {
        return JSON.parse(JSON.stringify(this._tx));
    }
    /*
    @description
        Returns the transaction in hex format.
    */
    toHex(): string {
        let buffer = Buffer.alloc(1000);
        let offset = 0;
        let numberOfWitnesses = 0;
        //version
        buffer.writeUInt32LE(this._tx.version, offset);
        offset += 4;
        //flag
        if (this._isSegwit) {
            buffer.writeUInt16BE(this._tx.flag, offset);
            offset += 2;
        }
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
            let scriptSigLen = vi2h(input.scriptSig.length / 2);
            buffer.write(scriptSigLen.toString('hex'), offset, scriptSigLen.length, 'hex');
            offset += scriptSigLen.length;
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
            let scriptLen = vi2h(output.script.length / 2);
            buffer.write(scriptLen.toString('hex'), offset, scriptLen.length, 'hex');
            offset += scriptLen.length;
            buffer.write(output.script, offset, output.script.length / 2, 'hex');
            offset += output.script.length / 2;
        }
        //witnesses
        if (this._isSegwit) {
            for (let i in this._tx.vins) {
                let input = this._tx.vins[i];
                if (input.witness.length > 0) {
                    buffer.writeUInt16LE(2, offset);
                    offset += 1;
                    buffer.write(input.witness, offset, input.witness.length / 2, 'hex');
                    offset += input.witness.length / 2;
                } else {
                    buffer.writeUInt16LE(0, offset);
                    offset += 1;
                }
            }
        }

        //locktime
        buffer.writeUInt16LE(this._tx.locktime, offset);
        offset += 4;

        if (offset < buffer.length) {
            buffer = buffer.slice(0, offset);
        }

        return buffer.toString('hex');
    }
    toSignHex(vindex: number): string {
        const signTx = new RawTransaction();
        signTx.deepCopy(this);
        for (let i = 0; i < signTx._tx.vins.length; i++) {
            if (i == vindex)
                signTx._tx.vins[i].scriptSig =
                    signTx._tx.vins[i].redeemScript || signTx._tx.vins[i].script;
            else signTx._tx.vins[i].scriptSig = '';
        }
        return signTx.toHex();
    }
    toSegwitSignHex(vindex: number): string {
        const signTx = new RawTransaction();
        signTx.deepCopy(this);
        let buffer = Buffer.alloc(1000);
        let inputBuffer = Buffer.alloc(signTx._tx.vins.length * (32 + 4)); //txid + vout
        let sequenceBuffer = Buffer.alloc(signTx._tx.vins.length * 4); //sequence
        let specificInputBuffer = Buffer.alloc(32 + 4); //txid + vout
        let scriptBuffer: Buffer; //script len
        let outputBuffer = Buffer.alloc(1000);

        let offsetInputBuffer = 0;
        let offsetSequenceBuffer = 0;
        for (let i = 0; i < signTx._tx.vins.length; i++) {
            const input = signTx._tx.vins[i];
            inputBuffer.write(input.hash, offsetInputBuffer, 32, 'hex');
            offsetInputBuffer += 32;
            inputBuffer.writeUInt32LE(input.vout, offsetInputBuffer);
            offsetInputBuffer += 4;

            sequenceBuffer.writeUInt32LE(input.sequence, offsetSequenceBuffer);
            offsetSequenceBuffer += 4;
        }

        specificInputBuffer.write(signTx._tx.vins[vindex].hash, 0, 32, 'hex');
        specificInputBuffer.writeUInt32LE(signTx._tx.vins[vindex].vout, 32);
        if (signTx._tx.vins[vindex].addressType == 'p2wpkh') {
            const script = p2pkhScript(bach32Decode(signTx._tx.vins[vindex].address));
            scriptBuffer = Buffer.alloc(script.length + 1); //script len + script
            scriptBuffer.writeUInt16LE(script.length, 0);
            scriptBuffer = Buffer.concat([scriptBuffer.slice(0, 1), script]);
        } else {
            throw new Error(
                'Generate sign hash: Unsupported address type for creating script code'
            );
        }
        specificInputBuffer = Buffer.concat([specificInputBuffer, scriptBuffer]);
        let specificSequenceBuffer = Buffer.alloc(4);
        specificSequenceBuffer.writeUInt32LE(signTx._tx.vins[vindex].sequence, 0);
        specificInputBuffer = Buffer.concat([
            specificInputBuffer,
            new BN(signTx._tx.vins[vindex].value).toBuffer('le', 8),
            specificSequenceBuffer,
        ]);

        let offsetOutputBuffer = 0;
        for (let i = 0; i < signTx._tx.vouts.length; i++) {
            const output = signTx._tx.vouts[i];
            outputBuffer.write(
                new BN(output.value).toBuffer('le', 8).toString('hex'),
                offsetOutputBuffer,
                8,
                'hex'
            );
            offsetOutputBuffer += 8;
            outputBuffer.writeUInt16LE(output.script.length / 2, offsetOutputBuffer);
            offsetOutputBuffer += 1;
            if (output.script.length > 0) {
                outputBuffer.write(
                    output.script,
                    offsetOutputBuffer,
                    output.script.length / 2,
                    'hex'
                );
                offsetOutputBuffer += output.script.length / 2;
            }
        }
        outputBuffer = outputBuffer.slice(0, offsetOutputBuffer);
        let offset = 0;
        //version
        buffer.writeUInt32LE(signTx._tx.version, offset);
        offset += 4;
        //double hash input
        inputBuffer = sha256(sha256(inputBuffer));
        //double hash sequence
        sequenceBuffer = sha256(sha256(sequenceBuffer));
        //double hash output
        outputBuffer = sha256(sha256(outputBuffer));

        buffer = Buffer.concat([
            buffer.slice(0, offset),
            inputBuffer,
            sequenceBuffer,
            specificInputBuffer,
            outputBuffer,
            Buffer.alloc(4), //locktime
        ]);
        offset +=
            inputBuffer.length +
            sequenceBuffer.length +
            specificInputBuffer.length +
            outputBuffer.length;

        buffer.writeUInt16LE(signTx._tx.locktime, offset);
        offset += 4;

        buffer = buffer.slice(0, offset);
        return buffer.toString('hex');
    }
    /*
    @param
        {string} privKey - The private key to sign with.
    @description
        Signs the transaction with the private key.
        For every input, the scriptSig is set to the sign 
        script generated by the private key and the other 
        vindices are set to empty. Script field will be 
        set temporarily to scriptSig.
        After all inputs are signed, scriptSig field is set 
        to the scipt field
    */
    async sign(privKey: any, inputs: number[]): Promise<any> {
        privKey = Uint8Array.from(Buffer.from(privKey, 'hex'));
        let pubKey = secp256k1.publicKeyCreate(privKey, false);
        let compressedPubKey = secp256k1.publicKeyConvert(pubKey, true);
        let signatures = [];
        for (let i of inputs) {
            let sigHash = await this.createSigHash(i, 1);
            let sig = secp256k1.ecdsaSign(sigHash, privKey);
            let encSig = encodeSig(Buffer.from(sig.signature), 1);
            signatures.push(encSig);
            if (this._tx.vins[i].addressType == 'p2wpkh') {
                this._tx.vins[i].witness = p2pkhScriptSig(
                    encSig,
                    Buffer.from(compressedPubKey)
                ).toString('hex');
            } else if (this._tx.vins[i].addressType == 'p2pkh') {
                this._tx.vins[i].scriptSig = p2pkhScriptSig(encSig, Buffer.from(pubKey)).toString(
                    'hex'
                );
            }
        }
        return signatures;
    }
    async createSigHash(
        vindex: number,
        hashType: number,
        redeemScript: Buffer = null
    ): Promise<any> {
        let txHex: Buffer;
        if (['p2pkh', 'p2sh'].includes(this._tx.vins[vindex].addressType)) {
            txHex = Buffer.from(this.toSignHex(vindex), 'hex');
        } else if (this._tx.vins[vindex].addressType == 'p2wpkh') {
            txHex = Buffer.from(this.toSegwitSignHex(vindex), 'hex');
        } else {
            throw new Error('Create Sig hash: Unsupported address type');
        }
        let txHexHash = Buffer.alloc(txHex.length + 4, txHex);
        txHexHash.writeUInt32LE(hashType, txHexHash.length - 4);
        return sha256(sha256(txHexHash));
    }
    fromHex(hex: string) {
        let buffer = Buffer.from(hex, 'hex');

        let offset = 0;

        this._tx.version = buffer.readUInt32LE(offset);
        offset += 4;

        if (this._isSegwit) {
            this._tx.flag = Buffer.concat([buffer.slice(offset + 1, offset + 2)], 4).readUInt16LE(
                0
            );
            offset += 2;
        }

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

            let scriptSigLen: number;
            [scriptSigLen, offset] = h2vi(buffer.slice(offset), offset);
            // const scriptSig = buffer.slice(offset, offset + scriptSigLen).toString('hex');
            const scriptSig = '';
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

            let scriptLen: number;
            [scriptLen, offset] = h2vi(buffer.slice(offset), offset);

            const script = buffer.slice(offset, offset + scriptLen).toString('hex');
            offset += scriptLen;

            this._tx.vouts.push({
                value,
                script,
            });
        }

        if (this._isSegwit) {
            for (let i in this._tx.vins) {
                const numberOfWitness = Buffer.concat(
                    [buffer.slice(offset, offset + 1)],
                    4
                ).readUInt16LE(0);
                offset += 1;

                if (numberOfWitness == 0) {
                    this._tx.vins[i].witness = '';
                } else {
                    const witnessSigLen = Buffer.concat(
                        [buffer.slice(offset, offset + 1)],
                        4
                    ).readUInt16LE(0);
                    this._tx.vins[i].witness = buffer.slice(offset, offset + 1).toString('hex');
                    offset += 1;
                    this._tx.vins[i].witness += buffer
                        .slice(offset, offset + witnessSigLen)
                        .toString('hex');
                    offset += witnessSigLen;

                    const witnessPubLen = Buffer.concat(
                        [buffer.slice(offset, offset + 1)],
                        4
                    ).readUInt16LE(0);
                    this._tx.vins[i].witness += buffer.slice(offset, offset + 1).toString('hex');
                    offset += 1;
                    this._tx.vins[i].witness += buffer
                        .slice(offset, offset + witnessPubLen)
                        .toString('hex');
                    offset += witnessPubLen;
                }
            }
        }
        this._tx.locktime = buffer.readUInt16LE(offset);
        offset += 4;
    }
    deepCopy(tx: RawTransaction) {
        this._isSegwit = tx._isSegwit;
        this._tx = tx.toJSON();
    }
    genHashId(): string {
        const tx = new RawTransaction();
        tx.deepCopy(this);
        for (let i in tx._tx.vins) {
            tx._tx.vins[i].scriptSig = '';
            tx._tx.vins[i].witness = '';
        }
        const hash = hash160(Buffer.from(tx.toHex(), 'hex'));
        // const hash = sha256(Buffer.from(tx.toHex(), 'hex'));
        return hash.toString('hex');
    }
}

export class MultiSigTransaction extends RawTransaction {
    _pubKeys: Array<Buffer> = [];
    _n: number = 2;
    _m: number = 2;
    constructor(n: number, m: number, pubKeys: Array<string>, isSegwit: boolean = false) {
        if (pubKeys.length != m) {
            throw 'MultiSigTransaction: Too many or not enough pubkeys';
        }
        if (1 > n || n > m || m > 16 || m < 2) {
            throw 'MultiSigTransaction: it should 1 <= n <= m <= 16 and 2 <= m';
        }
        super(isSegwit);
        this._n = n;
        this._m = m;
        pubKeys.sort().reverse();
        for (let pubKey of pubKeys) {
            this._pubKeys.push(Buffer.from(pubKey, 'hex'));
        }
    }
    addMultiSigInput(
        address: string,
        txid: string,
        vout: number,
        signatures: Array<string>,
        amount?: string
    ): void {
        super.addInput(address, txid, vout, amount);
        this._tx.vins[this._tx.vins.length - 1].signatures = signatures;
        this._tx.vins[this._tx.vins.length - 1].redeemScript =
            this.generateRedeemScript().toString('hex');
    }
    async sign(privKey: any, inputs: number[]): Promise<any> {
        let signatures = await super.sign(privKey, inputs);
        for (let i in inputs) {
            let idx = Number(i);
            this._tx.vins[inputs[idx]].signatures.push(signatures[idx]);
            this._tx.vins[inputs[idx]].scriptSig = this.multiSigScriptSig(
                this._tx.vins[inputs[idx]].signatures
            ).toString('hex');
        }
    }
    multiSigScriptSig(sigs: Array<Buffer>): Buffer {
        if (this._n > 1)
            return compileScript([
                OPS.OP_0,
                ...sigs,
                OPS.OP_PUSHDATA1,
                this.generateRedeemScript(),
            ]);
        else return compileScript([OPS.OP_0, ...sigs, this.generateRedeemScript()]);
    }
    generateRedeemScript(): Buffer {
        return compileScript([
            OPS[`OP_${this._n}`],
            ...this._pubKeys,
            OPS[`OP_${this._m}`],
            OPS.OP_CHECKMULTISIG,
        ]);
    }
}
