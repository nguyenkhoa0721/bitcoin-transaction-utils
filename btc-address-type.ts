let addressType: string = '';
const mapping = [
    { s: '1', type: 'p2pkh', chain: 'main' },
    { s: '3', type: 'p2sh', chain: 'main' },
    { s: 'bc1', type: 'p2wpkh', chain: 'main' },
    { s: 'tb1', type: 'p2wpkh', chain: 'testnet' },
    { s: 'm', type: 'p2pkh', chain: 'testnet' },
    { s: 'n', type: 'p2pkh', chain: 'testnet' },
];

export const checkAddressType = (address: string) => {
    for (let i in mapping) {
        if (address.startsWith(mapping[i].s)) {
            return mapping[i].type;
        }
    }
    throw new Error('Address type is not supported');
};
