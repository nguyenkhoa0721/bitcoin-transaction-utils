import BN from 'bn.js';
import secp256k1 from 'secp256k1';

import {
    readUInt64,
    p2pkhScriptSig,
    p2wpkhScriptSig,
    fromBase58Check,
    encodeSig,
    sha256,
    hash160,
    generateScript,
} from './btc-script';

import { checkAddressType } from './btc-address-type';
export class RawTransaction {
    _tx: any;
    _isSegwit: boolean = false;
    constructor(txType: string = 'p2pkh') {
        if (txType == 'p2pkh') {
            this._tx = { version: 2, locktime: 0, vins: [], vouts: [], txType: 'p2pkh' };
        } else if (txType == 'p2sh') {
            this._tx = { version: 2, locktime: 0, vins: [], vouts: [], txType: 'p2sh' };
        } else if (txType == 'p2wpkh') {
            this._tx = { version: 2, flag: 1, locktime: 0, vins: [], vouts: [], txType: 'p2wpkh' };
            this._isSegwit = true;
        } else if (txType == 'p2wsh') {
            this._tx = { version: 2, flag: 1, locktime: 0, vins: [], vouts: [], txType: 'p2wsh' };
            this._isSegwit = true;
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
    addInput(address: string, txid: string, vout: number, script: string = '') {
        const addressType = checkAddressType(address);
        console.log(addressType);
        const hash = new Buffer(txid, 'hex').reverse().toString('hex');
        if (addressType == 'p2pkh') {
            script = generateScript(addressType, fromBase58Check(address).hash).toString('hex');
        }

        this._tx.vins.push({
            txid,
            vout,
            hash,
            sequence: 0xffffffff,
            script,
            address,
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
    addOutput(address: string, amount: string, script = '') {
        const addressType = checkAddressType(address);
        script = generateScript(addressType, fromBase58Check(address).hash).toString('hex');
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
        //witnesses
        if (this._isSegwit) {
            buffer.writeUInt16LE(this._tx.vins.length * 2, offset);
            offset += 1;
            for (let i in this._tx.vins) {
                let input = this._tx.vins[i];
                buffer.write(input.witness, offset, input.witness.length / 2, 'hex');
                offset += input.witness.length / 2;
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
    async sign(privKey: any): Promise<any> {
        privKey = Uint8Array.from(Buffer.from(privKey, 'hex'));
        let pubKey = secp256k1.publicKeyCreate(privKey, false);
        for (let i = 0; i < this._tx.vins.length; i++) {
            let sigHash = await this.createSigHash(i, 1);
            let sig = secp256k1.ecdsaSign(sigHash, privKey);
            let encSig = encodeSig(Buffer.from(sig.signature), 1);
            if (this._isSegwit) {
                this._tx.vins[i].script = p2wpkhScriptSig(encSig, Buffer.from(pubKey)).toString(
                    'hex'
                );
            } else {
                this._tx.vins[i].script = p2pkhScriptSig(encSig, Buffer.from(pubKey)).toString(
                    'hex'
                );
            }
        }
        for (let i = 0; i < this._tx.vins.length; i++) {
            console.log(this._tx.vins[i].script);
            if (this._isSegwit) {
                this._tx.vins[i].witness = this._tx.vins[i].script;
                this._tx.vins[i].script = '';
            } else {
                this._tx.vins[i].scriptSig = this._tx.vins[i].script;
            }
        }
    }
    async createSigHash(vindex: number, hashType: number): Promise<any> {
        for (let i = 0; i < this._tx.vins.length; i++) {
            if (i == vindex) this._tx.vins[i].scriptSig = this._tx.vins[i].script;
            else this._tx.vins[i].scriptSig = '';
        }
        let txHex = Buffer.from(this.toHex(), 'hex');
        let txHexHash = Buffer.alloc(txHex.length + 4, txHex);
        txHexHash.writeUInt32LE(hashType, txHexHash.length - 4);
        return sha256(sha256(txHexHash));
    }
    deepCopy(tx: RawTransaction) {
        this._tx = tx.toJSON();
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

async function test() {
    console.log(fromBase58Check("n2UeDaa2pztrvYaBh5kEmc6bGwKM5CufL6").hash)
    // let tx = new RawTransaction('p2wpkh');
    // tx.addInput(
    //     'bc1q89apuheumszhf6fezlpu978avyuqv6m3n4edk8',
    //     '59505b56fa2602d58c4d50bf80db2ab94152b96c4892ead79c6a2e0d3ad5d0a4',
    //     0
    // );
    // tx.addOutput('bc1q89apuheumszhf6fezlpu978avyuqv6m3n4edk8', '30000');
    // await tx.sign('472778e9ff4521c485de10c739d32e760952c19d4669ac7128cc23feca28f4f4');\
    // console.log(tx.toJSON());
    // console.log(tx.toHex());
}

test();
