import { decode } from 'bs58check';
import { RawTransaction } from './btc-transaction';
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
    // await tx.sign('d1cb728032819c1be7158332930dec1e05e058220ae2659ccfc6f24b10cec077', [1]);

    // console.log(tx.toHex());

    let decodeTx = new RawTransaction();
    decodeTx.fromHex(
        '02000000000102bb84ae73691c8220d0ecebf534d04fbfe8bdeabb59882324fea3e49283c75480000000008b483045022100e58f1d48d429f276bbd0d0de004d51f77194e5ed3052f9dd2c38b9c51f90f5b3022062dac801afa6a5289c945f07e1192b2e29dc90187f76fef4b65e330faa6cd7a40141045b6e1e843751aa923ef3ff07525b01a591e2e2e3096ceee45b25401424e3c29f4de7b6311fdb8c07737822046e2a8650b21d7176ce332dbc2f27391af62e242affffffff42d6ba571ce8b4f6679f9b7700cd35cd28ef84c63f10f7fdebb26633bb0391390100000000ffffffff0228230000000000001976a914d0ac35cd083455c3ae094480d555fbc044ca33a088aca00f000000000000160014fad3fda8cc1964a35e4b3bae45189297b643865a000247304402201bc11d05de992136cb52bfc5877d76e59d8282e8a98635ef1a4624df462dc66102204b72f46271ace9b30d70b0071370b3219b15808469202a662c4ebec5288358f601210275fa9b990e27658b36b3606296ab1544bec630dd4c4f124d0ec74a6bc336ad3d00000000'
    );
    // console.log(decodeTx.toJSON());
    // console.log(decodeTx.toJSON());
    console.log(decodeTx.genHashId());
}
test();
