import { decode } from 'bs58check';
import { RawTransaction, MultiSig2to2Transaction } from './btc-transaction';
import { vi2h } from './btc-script';
async function test() {
    let tx = new RawTransaction(true);
    tx.addInput(
        'mzYK9KtKf6xawNEyf4M22YGxpYPQNFtsrn',
        '8054c78392e4a3fe24238859bbeabde8bf4fd034f5ebecd020821c6973ae84bb',
        0,
        '5000'
    );
    tx.addInput(
        'tb1qltflm2xvr9j2xhjt8why2xyjj7my8pj6cl6ezz',
        '399103bb3366b2ebfdf7103fc684ef28cd35cd00779b9f67f6b4e81c57bad642',
        1,
        '4000'
    );
    tx.addOutput('mzYK9KtKf6xawNEyf4M22YGxpYPQNFtsrn', '9000');
    tx.addOutput('tb1qltflm2xvr9j2xhjt8why2xyjj7my8pj6cl6ezz', '4000');
    console.log(tx.genHashId());
    // console.log(tx.toJSON());
    // console.log(tx.toHex());
    await tx.sign('f2bfcdab00c7bea417d47c5c05cebcce0fc8c37f3221725ed03bb2e4797cca74', [0]);
    await tx.sign('d1cb728032819c1be7158332930dec1e05e058220ae2659ccfc6f24b10cec077', [1]);

    console.log(tx.toHex());

    let decodeTx = new RawTransaction();
    decodeTx.fromHex(
        '02000000000102bb84ae73691c8220d0ecebf534d04fbfe8bdeabb59882324fea3e49283c75480000000008b483045022100e58f1d48d429f276bbd0d0de004d51f77194e5ed3052f9dd2c38b9c51f90f5b3022062dac801afa6a5289c945f07e1192b2e29dc90187f76fef4b65e330faa6cd7a40141045b6e1e843751aa923ef3ff07525b01a591e2e2e3096ceee45b25401424e3c29f4de7b6311fdb8c07737822046e2a8650b21d7176ce332dbc2f27391af62e242affffffff42d6ba571ce8b4f6679f9b7700cd35cd28ef84c63f10f7fdebb26633bb0391390100000000ffffffff0228230000000000001976a914d0ac35cd083455c3ae094480d555fbc044ca33a088aca00f000000000000160014fad3fda8cc1964a35e4b3bae45189297b643865a000247304402201bc11d05de992136cb52bfc5877d76e59d8282e8a98635ef1a4624df462dc66102204b72f46271ace9b30d70b0071370b3219b15808469202a662c4ebec5288358f601210275fa9b990e27658b36b3606296ab1544bec630dd4c4f124d0ec74a6bc336ad3d00000000'
    );
    // console.log(decodeTx.toJSON());
    // console.log(decodeTx.toJSON());
    console.log(decodeTx.genHashId());
}
// test();
async function multiSigTest() {
    const tx = new MultiSig2to2Transaction(
        [
            '0416d99e3d63a5f9793822232c6393e0fb50945b0c07946e20c7236cc0ce6ed786044083b9af68fecadfe45a03517e6730fdced867deee221ef7175be162706dd5',
            '04089ae61e4014c9588cae4bd0a6aef3d44b1be674a1aa27cf9d8b50b1bb422026da4dc276e11823f531f84842d4b990380cc600ad99fe84fe2f2bbd927d98fe36',
        ],
        false
    );
    tx.addMultiSigInput(
        '2NERCTjns9kMGUrksHZagpKwb5VLiW4PRRv',
        'd09ea67f8c62629a0dbaaf9a7864d9a13374d683b30a42b1ac91e422eececa89',
        0,
        []
    );
    tx.addOutput('2NERCTjns9kMGUrksHZagpKwb5VLiW4PRRv', '60000');
    await tx.sign('9626d2c1b8a2f2c0a7753a50980f96c8dcb4dddc622716bc50f6e72fe949dd0d', [0]);
    await tx.sign('c00e2f845866c2f370e2e9648d996e0c022a50f104917e75255dcff034a5cdc9', [0]);
    console.log(tx.generateRedeemScript().toString('hex'));
    console.log(tx.toHex());
    console.dir(tx.toJSON());
}
multiSigTest();
// console.log(vi2h(9).toString('hex'));
