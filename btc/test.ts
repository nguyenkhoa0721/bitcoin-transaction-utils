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
    await tx.sign('f2bfcdab00c7bea417d47c5c05cebcce0fc8c37f3221725ed03bb2e4797cca74', [0]);
    await tx.sign('d1cb728032819c1be7158332930dec1e05e058220ae2659ccfc6f24b10cec077', [1]);
    console.log(tx.toJSON());
    console.log(tx.toHex());
}
test();
