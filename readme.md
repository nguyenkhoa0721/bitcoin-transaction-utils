```
import m25 from "m25-transaction-utils";

/*
    @param
        isSegwit: default true
*/
let tx = new m25.BTC.RawTransaction(true);

/*
    @description
        Add input
    @param
        address: string required
        txid: string required
        vout: number required
        amount: string defaut 0
*/
tx.addInput(
    "mzYK9KtKf6xawNEyf4M22YGxpYPQNFtsrn", 
    "8054c78392e4a3fe24238859bbeabde8bf4fd034f5ebecd020821c6973ae84bb",
    0,
    "5000"
);
tx.addInput(
    "tb1qltflm2xvr9j2xhjt8why2xyjj7my8pj6cl6ezz",
    "399103bb3366b2ebfdf7103fc684ef28cd35cd00779b9f67f6b4e81c57bad642",
    1,
    "4000"
);

/*
    @description
        Add output
    @param
        address: string required
        amount: string required
*/
tx.addOutput("mzYK9KtKf6xawNEyf4M22YGxpYPQNFtsrn", "9000");
tx.addOutput("tb1qltflm2xvr9j2xhjt8why2xyjj7my8pj6cl6ezz", "4000");

(async () => {
    /*
        @description
            Sign transaction
        @param
            privatekey: string required
            array signed input index: string required
    */
    await tx.sign("f2bfcdab00c7bea417d47c5c05cebcce0fc8c37f3221725ed03bb2e4797cca74", [0, 1]);

    /*
        @description
            Convert raw transaction to HEX
    */
    console.log(tx.toHex());
    /*
        @description
            Convert raw transaction to JSON
    */
    console.log(tx.toJSON());
})();
```