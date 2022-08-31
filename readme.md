# Create raw transaction
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

# Create MultiSig n to m transaction
```
import m25 from "m25-transaction-utils";

/*
    @description
        Create Multisig n to m transaction
    @param
        n: number required
        m: number required
        pubKeys: array<string> required
*/
let tx = new m25.BTC.MultiSigTransaction(2, 2, [
    "0416d99e3d63a5f9793822232c6393e0fb50945b0c07946e20c7236cc0ce6ed786044083b9af68fecadfe45a03517e6730fdced867deee221ef7175be162706dd5",
    "04089ae61e4014c9588cae4bd0a6aef3d44b1be674a1aa27cf9d8b50b1bb422026da4dc276e11823f531f84842d4b990380cc600ad99fe84fe2f2bbd927d98fe36",
]);

/*
    @description
        Add input
    @param
        address: string required
        txid: string required
        vout: number required
        signatures: Array<string> required
*/
tx.addMultiSigInput(
    "2NERCTjns9kMGUrksHZagpKwb5VLiW4PRRv",
    "60684db3b0558555b45c8e42930d6a25a63595618ac721736faf5f04df54fb27",
    0,
    []
);

/*
    @description
        Add output
    @param
        address: string required
        amount: string required
*/
tx.addOutput("2NERCTjns9kMGUrksHZagpKwb5VLiW4PRRv", "35000");
tx.addOutput("tb1qltflm2xvr9j2xhjt8why2xyjj7my8pj6cl6ezz", "20000");

(async () => {
    /*
        @description
            Sign transaction
        @param
            privatekey: string required
            array signed input index: string required
    */
    await tx.sign("9626d2c1b8a2f2c0a7753a50980f96c8dcb4dddc622716bc50f6e72fe949dd0d", [0]);
    await tx.sign("c00e2f845866c2f370e2e9648d996e0c022a50f104917e75255dcff034a5cdc9", [0]);

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