//! NIST CAVP known-answer tests for the legacy RSA PKCS#1 v1.5 / SHA-1
//! verifier (`latticearc::primitives::sig::rsa_legacy`).
//!
//! Source: NIST CAVP "RSA (FIPS 186-2 and 186-3) signature" test vectors,
//! `186-2rsatestvectors.zip` from
//! <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip>.
//! Every `[mod = 2048]`, `SHAAlg = SHA1` entry is copied from two files:
//!
//! - `SigGen15_186-2.txt`: 10 signatures generated with one key; all valid.
//! - `SigVer15_186-3.rsp`: 18 signatures with `Result = P` (valid) or
//!   `Result = F` (message, exponent, signature or encoded-message changed).
//!
//! Each key is checked through both accepted encodings (PKCS#1 and
//! SubjectPublicKeyInfo), which the test builds from the published `n` and
//! `e`. The legacy verifier is compiled out of `--features fips` builds, so
//! so is this suite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

#[cfg(not(feature = "fips"))]
mod cavp {
    use latticearc::primitives::sig::rsa_legacy::{
        RsaLegacyError, RsaPublicKeyEncoding, verify_rsa_pkcs1_sha1,
    };

    struct Key {
        n: &'static str,
        e: &'static str,
    }

    struct Case {
        source: &'static str,
        key: &'static Key,
        msg: &'static str,
        sig: &'static str,
        valid: bool,
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![u8::try_from(len).unwrap()]
        } else if len < 0x100 {
            vec![0x81, u8::try_from(len).unwrap()]
        } else {
            vec![0x82, u8::try_from(len >> 8).unwrap(), u8::try_from(len & 0xff).unwrap()]
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(der_len(content.len()));
        v.extend_from_slice(content);
        v
    }

    /// DER INTEGER from a big-endian hex value (any length, leading zeros
    /// stripped).
    fn integer(hex_value: &str) -> Vec<u8> {
        let padded =
            if hex_value.len() % 2 == 1 { format!("0{hex_value}") } else { hex_value.to_string() };
        let raw = hex::decode(padded).unwrap();
        let start = raw.iter().position(|b| *b != 0).unwrap_or(raw.len() - 1);
        let mut content = Vec::new();
        if raw[start] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(&raw[start..]);
        tlv(0x02, &content)
    }

    fn pkcs1(key: &Key) -> Vec<u8> {
        let mut body = integer(key.n);
        body.extend(integer(key.e));
        tlv(0x30, &body)
    }

    fn spki(key: &Key) -> Vec<u8> {
        // AlgorithmIdentifier { rsaEncryption, NULL } (RFC 3279 §2.3.1).
        let mut body = hex::decode("300d06092a864886f70d0101010500").unwrap();
        let mut bits = vec![0u8];
        bits.extend(pkcs1(key));
        body.extend(tlv(0x03, &bits));
        tlv(0x30, &body)
    }
    static KEY_0: Key = Key {
        n: concat!(
            "e0b14b99cd61cd3db9c2076668841324fa3174f33ce66ffd514394d34178d29a",
            "49493276b6777233e7d46a3e68bc7ca7e899e901d54f6dee0749c3e48ddf6868",
            "5867ee2ae66df88eb563f6db137a9f6b175a112e0eda8368e88e45efe1ce14bc",
            "6016d52639627066af1872c72f60b9161c1d237eeb34b0f841b3f0896f9fe0e1",
            "6b0f74352d101292cc464a7e7861bbeb86f6df6151cb265417c66c565ed8974b",
            "d8fc984d5ddfd4eb91a3d5234ce1b5467f3ade375f802ec07293f1236efa3068",
            "bc91b158551c875c5dc0a9d6fa321bf9421f08deac910e35c1c28549ee8eed83",
            "30cf70595ff70b94b49907e27698a9d911f7ac0706afcb1a4a39feb38b0a8049",
        ),
        e: "10001",
    };
    static KEY_1: Key = Key {
        n: concat!(
            "a911245a2cfb33d8ee375df9439f74e669c03a8d9acad25bd27acf3cd8bea7eb",
            "9dbe470155c7c72782c94861f7b573cd325639fb070e9ba6e621991aefa45106",
            "182e4d264be7068035595d7549052989b3e7fd04cabc94012c1278a0ef8672b1",
            "a51dd1a9e276816ba497dea24b4febe3dd8e977707bcd230ca6fb6f8a8bff9e6",
            "ba24fbadcd93f00126b19b396a38e6ef86d18fef945b9154c1963fb488c70259",
            "53511f86d05638bfe056493730bc6778446e59cd3c5c3acf07a0a3a649437936",
            "52f10e3292aa7a6d25a03181cc6f6ba0658d909e59ce2a02bacc9766fd8c4fbd",
            "4ed9c23a866844b8a794d49e505f9f944870a71aadbe5338039825c2dff81af3",
        ),
        e: "10001",
    };
    static KEY_2: Key = Key {
        n: concat!(
            "a911245a2cfb33d8ee375df9439f74e669c03a8d9acad25bd27acf3cd8bea7eb",
            "9dbe470155c7c72782c94861f7b573cd325639fb070e9ba6e621991aefa45106",
            "182e4d264be7068035595d7549052989b3e7fd04cabc94012c1278a0ef8672b1",
            "a51dd1a9e276816ba497dea24b4febe3dd8e977707bcd230ca6fb6f8a8bff9e6",
            "ba24fbadcd93f00126b19b396a38e6ef86d18fef945b9154c1963fb488c70259",
            "53511f86d05638bfe056493730bc6778446e59cd3c5c3acf07a0a3a649437936",
            "52f10e3292aa7a6d25a03181cc6f6ba0658d909e59ce2a02bacc9766fd8c4fbd",
            "4ed9c23a866844b8a794d49e505f9f944870a71aadbe5338039825c2dff81af3",
        ),
        e: "3",
    };
    static KEY_3: Key = Key {
        n: concat!(
            "a911245a2cfb33d8ee375df9439f74e669c03a8d9acad25bd27acf3cd8bea7eb",
            "9dbe470155c7c72782c94861f7b573cd325639fb070e9ba6e621991aefa45106",
            "182e4d264be7068035595d7549052989b3e7fd04cabc94012c1278a0ef8672b1",
            "a51dd1a9e276816ba497dea24b4febe3dd8e977707bcd230ca6fb6f8a8bff9e6",
            "ba24fbadcd93f00126b19b396a38e6ef86d18fef945b9154c1963fb488c70259",
            "53511f86d05638bfe056493730bc6778446e59cd3c5c3acf07a0a3a649437936",
            "52f10e3292aa7a6d25a03181cc6f6ba0658d909e59ce2a02bacc9766fd8c4fbd",
            "4ed9c23a866844b8a794d49e505f9f944870a71aadbe5338039825c2dff81af3",
        ),
        e: "11",
    };
    static KEY_4: Key = Key {
        n: concat!(
            "93397894e668653afab24bf55c15071960a81157e680444891c42ac0cebf9ff9",
            "9e3739e12d0223d62ea048e77ee284582a707050fd11258f27fb6a4e2b583ab3",
            "7ed0799708e3379e41b191092b2f4631c974dfe81993c740f21bbd0d828ad398",
            "893aa33101f445e5ff02ca498b8a851100e8d50aa2fe4c88ee38be966222657f",
            "943f9bed73f018a4fd371d208c362cb2aa4d1cec9c68f8416ef00ded34f4a1ee",
            "4d59a8ff4c5b3deb33c504542dfbd772ac649c8313644a32205a602cb5581819",
            "e4f4a2b8150e63e20669690429a4b5cc77577295183ff6b760a1b5fb989f1581",
            "07860751c7808c54c1c511d3057b5e9537e009576b723dc9073c0b03f28955e7",
        ),
        e: "3",
    };
    static KEY_5: Key = Key {
        n: concat!(
            "93397894e668653afab24bf55c15071960a81157e680444891c42ac0cebf9ff9",
            "9e3739e12d0223d62ea048e77ee284582a707050fd11258f27fb6a4e2b583ab3",
            "7ed0799708e3379e41b191092b2f4631c974dfe81993c740f21bbd0d828ad398",
            "893aa33101f445e5ff02ca498b8a851100e8d50aa2fe4c88ee38be966222657f",
            "943f9bed73f018a4fd371d208c362cb2aa4d1cec9c68f8416ef00ded34f4a1ee",
            "4d59a8ff4c5b3deb33c504542dfbd772ac649c8313644a32205a602cb5581819",
            "e4f4a2b8150e63e20669690429a4b5cc77577295183ff6b760a1b5fb989f1581",
            "07860751c7808c54c1c511d3057b5e9537e009576b723dc9073c0b03f28955e7",
        ),
        e: "11",
    };
    static CASES: &[Case] = &[
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "544be0a4044edcdc1240f2182109f826d784ea613486dfd5221d3ba44d1525a9",
                "34c13c5a81f885f3955da8d168e35d1b909121a89f832d1db232a85647f51c08",
                "4fc727a4854a737efd0ce72e00091f3617721ae666ad337d3b9d5391e72364b1",
                "cde50948b84e8cc472d618f8928328bf95af3fe3300dda3de5e7a21dd5a9e7ec",
            ),
            sig: concat!(
                "d0d03ccb3b30b7c9c4d6eeee2ec26d069246e019fb8fa2f3a9b72c9bbe231d93",
                "ce053df805a045e2ef6bd8d08bfb0c36922e5a6f10b947b2607f596b6cbd3c9e",
                "efef56f5396805e8b28b1ca182c78c0b12b9796aa856af69c35504f8acc7afa7",
                "4bc0f77a1d61da94944057a9ee72d2f0a96cbaa2f64676f5318b71e56f519d0d",
                "a1ce8f42db0ebe5045fcc726e39fb0032f2287918f9190f3fb3d4de542030441",
                "f6736c6205a2bcd2450eb411085311c7320baa4268fd2fd8bcc8ebfddbb60740",
                "cff0b3b00f618777ebcfb3468f309d923c957c8170727a5458ac2c9070f93cfc",
                "37d31cf9f1a35d0cc3abf25af8dc9e1590ce59ab39d01cf0c154ab8d0635c5e9",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "8a66370970925dda75609a710ad1fa75d04e523c508f8cd6ecbd3f4d15d3832b",
                "bf4a033d12f55397632a84d86222f6af95a26e9e05db68fe3790af445d762a82",
                "cee0f931b49bc12d04174301b4c8346528cc4805edce9184a92a07c152526859",
                "9f70426dbc4d4da54271ff74668c5b9e71140af87030ac6f2cd5704c5c2ee2b7",
            ),
            sig: concat!(
                "16da730c7ee6f3f9750aa3120f734f7800f2cbf7247c180f1a490eeef5dc637d",
                "d2da577cb2f41464adeadabcbc7324779a2b118c0c61c2829b55797de6a3b092",
                "aeea444d2b4080f15614e9da6eea17552a8e955fcec1873cd20bfed8ed2d63a9",
                "50b159a0ac109df370ddea773a7149f1893cda82d84ace35b65b3fa9f7e4cebe",
                "c8e219ba9a12fac5cf5b2449cb6d563d8a646f1d649dc9abeac829a3ce8f9823",
                "cb70877193690855389557adbdbede90df0c274986f09796abc2a2b16f7c8c6e",
                "b5b3a42b0958c3da16bc363ed45de4ff4357dd8c20421e4c3007f9b98c86a80e",
                "7ad0106aea059acb71ed2d81eb6f0dd758bdd9d508cc465e23404aeb08e4ddc5",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "a8f41af433ff314d93e0d1e0bc05c427cb682697f6b705ddc3b32a6779d63526",
                "d438f092fdb3ddefb94511cfe1b745d9127c2bc8a5dcfeb7e2525d9b70325911",
                "108ecd5a8c5beea3e9d0228ae40f16df9d070aa78d997067bdf9b69f3a586094",
                "c4c05952c63f8bf28b47ad19ae555cc1d2d16e3c94358375be72dc7abd907137",
            ),
            sig: concat!(
                "2d69d08bb9b99a173a69a3221c28958161f5defd5592e3ef5cf0ef21f04ef7e1",
                "99344457b363206bc2785197489aa83d0b330618b5d58edc9ffca4268a1058c4",
                "b1d1fdb39ea2a1afcf2024da3c9e1f9820e65721db4a0accc77254291239c83b",
                "46fd3af6ab14aa2e8c4e140f751744bfa731d2bebc33d30388f140e8111ce1f7",
                "a090005d78b48feaedc0059897e3384a3a31270eecaabf455f60b8377619cdd7",
                "9484c292562a461ea96774e9883253d611dd4e7b26af83d19d740cd41f26d28e",
                "ae5d20a85d16b374b991b03141ba87c75da6d23818f509a2547f2c3499eeb48d",
                "d48363f3f80bf15f2e2328116940a0c3f4d4ca6726c92814bbfd94ebade849ba",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "9044d199a837832558657fdf67c8ea224f41317eef7f54ba84228519d620f1dd",
                "af68de0a91c6f66ca807e2dbfe5d1bbeee05fdcedb261e1d22fddd564c373e46",
                "899ef59b5af8c0ec8d2cfafa6ea76e363cfe6983dad5133cc7fffe7950e7008e",
                "042e3ed569958aaeed1eefc31f6e89911f769a245352db215c71100a49f7dfbe",
            ),
            sig: concat!(
                "176fbaea69c599caf946fc657b1fc958565ef3195931843dcfe5031b15d4c7a9",
                "6c005da15f6f6550e5c426ec91c871b1c8dd0868cfd1de3b7901ce6c16fa2d39",
                "b1caeb3a479741893e8165910b46f07a9acb29d3a7b82ee6a1e06bf44155a8fc",
                "025480fe495eabce19e6728c5f3d812b32a7a14dfe79925351082406e14c7f59",
                "1d931f1c514980e964691a51e2044ebb82c40eaace62ff74eb66b2dbfc15a08e",
                "a48c7a2a110fc402b7a68cf039c8eaaf437d5642a3511d36bc12f96cb5b6cff4",
                "7c5614ef7cc2be1f139047a7c5dbfb1d7018fb8857216662d3f5af3f7e1cc696",
                "e9b1ec958295218448e19625a1e65ae92be6d60fde3d2e6a0b3093efcc7754c9",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "b796c34f1d4e1dfb3010282bee33eb9da90e73f7ff186b0c0d4eed5be0d598d8",
                "2ce1e3f041d5b0c73aac25c47897b74f4fe787d9fe2ef21de5a163a6f2c16c92",
                "5d3b1695950c75417ae87f84ccdd1e72e3348344a198bea1a67a8b1dc2b36f00",
                "b06b0448013a91f1568ede73d24d478dcfbb0e41d09df620b79f0dc739f3c9aa",
            ),
            sig: concat!(
                "9e324f827ca17e50fb0cd17b8f714d7da1928e1c586a83d437e9891c78664463",
                "8af225e92841ca1df6d94e6eed65b5f076cae3aeb97ac96f003adddef6cebe80",
                "de99c584849a1c1832813cbb63fc619079252ad4d8881ef72e630ea06fb3b0e1",
                "b51bfa379b1decfb92e964cdc68809afb9d53b3c43dad119ba67b5ec1ace1093",
                "fe2e144d498b81125fa69b51814fa3c1230f0b42f9d7763b1447ec57bd0d93a9",
                "6a8928bb7f4560be95fc100dc6430674107511f7f466a18fe102a7bb0c3536ee",
                "9d3a7c45631153cccf774fa65f20d07a5255a0902d4dd3c91cda03c0778dd727",
                "8beeab6afb93cbce0c9fd6b202d57d811dd7ee50331f7243168df107597d25a6",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "4b6308be5b3d99ee6785bcce2566047ad96adf7680e26b364e878be45b613b5d",
                "9ae8207d0a6a639c30acc058c4d4da95ab86d2c3254e1760483e80bdadd89804",
                "692e397a3e475c0213c52fe3a2c568ca7107d913034f45444f0a73da71358049",
                "a07b793e609d2a27f81730f52701562013331eec82ac9dec4c358cc411419d32",
            ),
            sig: concat!(
                "ac402ca58c3a5e42bafb2135503a176174cf1bb86d5bc4a5d7f6b3e41251c0a6",
                "179df8696bf418ac2ebb52682a8b5f3cd23f0e1afb58c8b1996d486b90bfdf6d",
                "7c1e5e25575ae5b370ea3437d54a2f98f96d99ac601fbb93dc81c731fa10a615",
                "8baaf040fe57184fa79af7a4ea3606b08b329ca455f35cdf5cae9a9791e8d70f",
                "03ed8226031d7de352ec4b999e113c23e9ec16cce9ab1baf49ca090abf009389",
                "561d25013963f93d182c1b8e3ab6d8c563e6f8ebba125281e93a1f5b84f370eb",
                "b51b03e36212697b32b7c272f6e4dc0be86364020b659b1dcb3604322af2d512",
                "2e3b6b68cb26ec8abb4ead01f9b13d8a1a7db29331b1ce9b560158b4d89bb961",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "693b3235e6576d1f9d17b9d200b9b289306a1f03c0ffd2d7bce5d008e95bb2d9",
                "4fde4be2f5e58b64eccfa3da8e1a6ad008d500f81658b17b0e321c8d20639444",
                "dcccc6aaf4e39c1144ab62a60fe428498c7e679ca154e75aee17dfeb0d885f35",
                "18ebebb46cb868cdad933d5f0b7eb29cc34e9b17e85b3b1d637c63493933da53",
            ),
            sig: concat!(
                "54b78bec4855765b4c51925778abcc0275b6e9f55419bb54ad66f0d8e7f3cf68",
                "cd3d5b299e634b2b26bb78fe9eaeb6f8826cece71562f9760554c9b2dade5492",
                "2a367a937dd9c99e60df11a5daf4b10f6e756961f2bbff96d5ca3933b3bab13c",
                "338a46469c8b5118e8e2b06b57f0487c23a5d145c3308989d8e469690ebfb140",
                "1989b5677d1b9262f0a62d38753041ca6eb09069d4a679eb68d4d9ee7b64fc1e",
                "1c8260fcbaeeaa83c88ea603109e76c885e8ba1ee99ba1fdf37a7932398341f5",
                "9771efca036bd9921957ec7b972125eecf2319f0ce39d4de21fd78e98574794d",
                "eadd8f55bb8c03f47592d6877a1fa0b66d6d8009ecfe58a71fc07e021505e8ad",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "c7960decb793f6d8414918eae60716868bee1c7dcdf9ce30943b7ff9eb68a4c6",
                "0f978807c54641cbf19fe22565faf2d5f7a21d24d6dc2a101e252da9a9bcfebb",
                "2960e9ad735ba7a91ebf8dfe4df004c2c96239bb53a41680389e70db25178272",
                "3d7a9aa669d912bcef32823a47f134942ab7d808eb5a79c70a2db05507811832",
            ),
            sig: concat!(
                "de64be44ee64131b4efcc32982ed33b52e58f3169139d002f9b61160dfed8cff",
                "955acdcf28165a997959491d9b20d03e4e297289a68efb1e9ec3476ae7253ffc",
                "e743ba4abe64c1c71310d6a812b75eaf2c18e6745da146da87e85280ed8cc01f",
                "4330d51b1e77231e25021b7712793f6e875eb7233b11c9c003da5978f6af3dc5",
                "1cce8249ec53bcaefb3a52c9b9ef9392a89051bb0bfa67cf3275318d35ca44dd",
                "71a5d67809be05c054ac97c5a6f65f73b7fe142495260c882cf9f5d5b455b226",
                "12021b036e1197803dfb1b45c522b69156dc549974b865c2d66d3871cdb7cbb1",
                "2ab5bb30931a9710b2ffef326b3954872a56eb4e6274ba4bc40a1c19ca154cd0",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "6278d8bc32dc6b039f138c9260c8c90d98607fafaa824cea4fd7c74de60e6fab",
                "0b24e27a6ae25079d5a72e9695672f0efef470d6477cf23a98534ec463f3a45f",
                "f842d5bc5413f2f53aeef4708614ad07bdbefe65e8a64bb3a3c82c75716a65ae",
                "525a194b98773abef67244eadad62b3ffc46912637063d9f99bec928b67a9ae2",
            ),
            sig: concat!(
                "98ff167b985e030585d170aa38a1f85fbfdede90cb57f5240876aa8ae669177b",
                "917dbf8fc00852bf85116cbb9002f465dc09b340d3bf1a7f96f87fe7843d78e3",
                "224af76108d238260598b2eee93055593b714b0f3f422779155668ddcc2078c7",
                "4cf935a298619c661a9fd313bdd5a65ac4edde4625142905029402a3bfbc111e",
                "16cf403552abf2af3bd11554e50d5809cc13af82ae894113dd04c65605de2216",
                "bbf66a08400566451f4254eeb02294f8f86be0600f35349d919a26272471c259",
                "43b53147cdd102d268ffc7b3cf98738d837823831109adb4593aa38650622ce8",
                "b64e94db3ed35000fe3c8c6cd068009fd707d23b5f94d0b3382e207a98e255b2",
            ),
            valid: true,
        },
        Case {
            source: "SigGen15_186-2.txt",
            key: &KEY_0,
            msg: concat!(
                "e823b2f062bb10a41f3ab2a0c4bd110b2dc2846f0f3a066adbe039a6e5c8ab0a",
                "c53b5832fdc2711ddd815c26a4c6fc36e8e232373838a4ccff93bd3fabbdf5bb",
                "0f4d52bb06c02ec25acb3c4de4f0c605f450383af3c0e28d461efaec76e6e0c4",
                "8e00a671c5dcd0fa5dc158fbcb62f6e218b39e5e87fa49157829f8968c6bf68e",
            ),
            sig: concat!(
                "86f4b5c9b7db9cf7d09caae1ad6ab3043ce39d14c56c6e4fd8701a8eefd66a17",
                "92c89cc105f3657298b293894e999fb30e30079aebb1d4fa0f5c6fcd5096f505",
                "74592696a559d0f228d18d4ae8f75b508b714ffb3393a4e560b0d004bc4a0129",
                "387babee466e0c9b1a223f3a87450de0e4200733af92745c880a155f6d9cabba",
                "816181078fe4cd360ba25a45954f4b52356435964789f9503f889799e55a3f3c",
                "46fa32c5195c84956e56913cad423dc4c8a6ed7f17f1825bbdc53dd33d3c3b26",
                "12da4ce5e89622d62aa0205ee667a9dee276b91dc7bc67a8c1b379930aea8c8d",
                "26c4773fde955e4afc371197dcd8cfd6c619c2f0f57c0b2fa08ea73cc18c156e",
            ),
            valid: true,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_1,
            msg: concat!(
                "04d5d202ade6be1df96d263021141bd6e4e68a14c5b413df73b817df89791373",
                "77ee2df5c0e60d3f67a8ee6ea3d6f5e6da97c196cdf4437d1183d06cbe43740e",
                "6bc88a2759988919eed421ac651b870ec5ab0d190fc9f5d5bc64873e66f56147",
                "c6a90f1edec2dbb2773ae673ceaa78588b6b9527f2fbd1f15da265dbea558125",
            ),
            sig: concat!(
                "6b2703ff1a8d96808bf97eb6d297a8b8d11f479e22b8471e03d2713d124f7c8b",
                "f46225e8de2b9db432c39209c242420bc9a17196a38c1b2daa096a73e33912b3",
                "53a6adf9d198d15eadb6f287c5d2379fe8c07d9e5735bc4c474c2ff9bc7ee6d3",
                "684335f7f825664d6272426b2fa20bae585f7bb306b352d916679c68c77ce0d2",
                "032cee4909fd02f4f4711ff4e771251c3a9e284f37fb1bd417d8842d030500d8",
                "4bf7a774b5bbf089e2829c7e7dc27f4d88408e5b549522339e6eb98d51718a21",
                "9c0fdc20e26bb32d85ef877a5fae812ece7bb04a1ac5a0dd71ae4e8d4c25aacc",
                "f8c1f5b9c0de7e0491cd754a675ab6eb8c630b8afc49e0597ea6cacc6c37fe9f",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_1,
            msg: concat!(
                "3efa6c9938d6bc37f0373d0baba3697acc3bed498f9dfea7fa0af06e11c405a6",
                "4aba834b4067094fabf822e390ad1bf3b58112ef580d50d120aad95c54d640a1",
                "4bd9c0c824a8890db7095809caf84a338949f2a63090a9250b3e255ca00c4e68",
                "2b9d4c9a4a5ee578fab20605c24c9f432edbb4f57fedb2a9a10dfff65d2fd403",
            ),
            sig: concat!(
                "343014b8db6ba664af3dc07530e444976bac0a7fd3505218500b0342c0c861d5",
                "08f55383c18ee70cf47516acabd50dbc2ec18a8cc2054ab87496b9cf22e4f576",
                "d5f208d0cd3be114f65f69e0ae744e46edbe0a378942e24eb51fbe25a0caeb65",
                "4b20ce9a8feda1bd02981a24ed35fd139d107611cbdecc7b1a960ec57a19eef7",
                "9bac1ed277b746772b405c7c29cf8e32c1c7a49557928ec792944bbc87183fe8",
                "28a3469214fd35c8ca16df57a985d610ef80db9728f3d31529a7c39da03d39a6",
                "735117dc99225921d26fcee7779d7ae191934452207bddaa60c0aadef72c1ea0",
                "9d5a1d7cac615a8a5b08c5e429d801f868683a72263d80db270a413a8fd9c4d8",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_1,
            msg: concat!(
                "0017191f1c6b5bdf895837a17e05ca6119ea3606aedb978c5f423962ecac0811",
                "cc87471f7c2985331715cd79277a1e48bafd1a03b9b8023d7683e2208472090f",
                "cb9fbc8adb292c52817ca5ce98d307ae22fc7ace985b5e5d7e32813e392095ae",
                "25e7e128e3723685f01625687c186fd9796fbd30f2cc91359ed87d85b5bc9338",
            ),
            sig: concat!(
                "1d2db922b68b7e89cdef4a238e033500962d61cd39bcad53494663921ae6b0f7",
                "710728d9dfb8d52d7725d4f11ca058b1195b1c3c4614c32dce6a2b1b9ad1db26",
                "1bfde9cc8258787fa7ac9884ffb5e69775ee76ae8af3a15254898e8497b77d7c",
                "db161415a1615eec8ae7ba4ffb352ba459a1d84e43a04b616a13cac644b38c52",
                "8047841e249ff2795ef2fd066615828545d04c82e92a027bc110c5de6a52355e",
                "02bd7888c97dfd48a925528e48890323c6a4f44e5d04ea05cf3009e838a6bf43",
                "8fad103ea8ffe8d0f7d770c0034de693c7bbad16e8c6a923cc8976bda5bc08b1",
                "5897075162068b39b362699149e0cd4eda9ff1bade4fb540dc27c17e4119708a",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_1,
            msg: concat!(
                "1577757d0f460af152dc68b6ab25deadfebba5f68351bb6e2e51ee766fc437f7",
                "1c734aa3ac4b6b7da506839b5708732acb87a8b4f7eff09e33858cf5f14a866a",
                "a822459a11355e939696ad940823a51590ace407e8570a5dca42cccba96b44ce",
                "a0cd8beca8cc8a3d0dd30d2a233c19753570807abe4fb2b4dbd2d68201ee1a2b",
            ),
            sig: concat!(
                "5322e332949c0f15fe63f09927e2ef90a0f1eb2262fc8a7dc602facf8b5cf74d",
                "d0eaa2638a6d4393c0167be176e8e68d3b1a6dd4c7f043dc81e702b3b2620df5",
                "a4032e6319ff88e19c9cf57fc03f3ec5ca75db70b6b22a38f40a3dc214b477da",
                "2e1400eba49c35323c8d83e5159eb4ca6701b4fdb99f18505f266ccdcedbeae5",
                "9b36fec2616b04da979376403a435d3aae0113d4605b9ffda0afe72923ed2644",
                "069a408c148b4e781387fe49f3103841eff840f0b39b298ab4893ba2c292af33",
                "b57f6f6f69cf5464be470f678ec07f0ae97c9ff292d896a7daec48cf9e48ecd0",
                "06acbc2c8567368be62f2178d469ae958ac0b5bd66917944c4b53d1f42ea2f20",
            ),
            valid: true,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_2,
            msg: concat!(
                "b72914feec0e16233c24031390fe31942537dfc03d58810915fb597b16314741",
                "4f22e26b23f3c7ee3fed32ecd0dbcb36f2b3c2106b791d3499615119a9341074",
                "0af4630021c3f87a3f01bdf0d0b5ae3cd52eeacc94ea0da48db6baa5b117770f",
                "cfe9be454f4650d022a9cda7f95382adb5ee827c1f71f861da43bba796a32319",
            ),
            sig: concat!(
                "2c2a5042129ef97c6235195df1da7b3d80e08176900daa562ea660258269e1a5",
                "5c73bf226fb54d21f28b8cc02aab8f453405f2c0ee6682ec8ff2d1d8540aec1e",
                "d953f53847bc43f0c89608164532da10188400e9e7850114ece817aa854024e6",
                "96fed5ff74a3747de548fe431d4a95c789bb377a8add64a8583dc7fb203fd66e",
                "c9e476232c25b9d454aa9ea7332672cde4ef7540b12ee28524b6c399be32805a",
                "c0f7f0db08eb07b93cd24a23baabccdbf5c8437fe2c3330586757a897242c8f2",
                "673ab8295ee88e5ec2222fd6519fc49cb1eea3d21d63f07d32bf0874dfdd5e74",
                "f511b2e06750ceafaef4238824f92c5da128042dbf64557cd6e4d7ee35d479b3",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_1,
            msg: concat!(
                "25d08c937abe386aa08b54cb9d7537829c478e53e67df73b0da9cbf76a153acb",
                "caaa9e7c6510099e10172016b3562dd7fc126fef5561b5c7148e2ba6f2c07378",
                "bfd7f7ce54977e25c808fe6be71cb1bfdf936b793d1c2b6a18bdf0658c74cefd",
                "6b1f40912e99c086322695d42111edc4ad932bf885f782ab81fcc33a207b73e3",
            ),
            sig: concat!(
                "93a032b6e997c0f9ed6261cc4617d98afb80cbd6450a3d9ea2f63999dd68194c",
                "9451538975d7626d77a34734d99b5992f98ed18c7f9dc0026fe34cf6583a6a36",
                "eb6baadb8316e3aa48d9da4244544da430cb8a19953d84ad4575733d887ed3bb",
                "cb4f25389cd36b1c565bf661b1c918a14e5e00e0f0857900ed4c98beab9fe6d1",
                "f66a0df588b61afae9fa31e94464d85bc743193303259e9806231cf5cdd4d4c9",
                "da5691c08156aa72f4da7607d598d450a5c852a8b3f577194afece74e59fd4ba",
                "8c5bfa583c2fa9a6f6aca7c51f772d02fe8e0bcaf5e4c2c7cdd6a38f7264d717",
                "aa2b30daa6968a4e7e7e2dcc1de9e34604f0b80c8b793f882d35497d81ade352",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_3,
            msg: concat!(
                "b756bc9af8682c9473fe98082ecb72f33f6199099baece582cc6672924e34727",
                "90a90dc330af8cd6863c7c882d4e6e726ce106ff0b6d641865b1e300bfaf067c",
                "d8f8af38c1299266efb6eaa88fe66a30191f772528649449891c1eda921539b6",
                "b5c80ac255df278bd7f44b2efd9c4f766fa455459b9a4735bf8f807e441cc81b",
            ),
            sig: concat!(
                "20aad3d29d4bdf75f18d3617771723419920e688928a0c742af8b11bd2e05767",
                "afa0256c868c3538111359b7bb91dbf1b8bfc383a1573cec0bf0c62837b13fb5",
                "df21e7e07bb5d758ba8d58171d22b46147d6f7bd3b8751e97ecf13a5bc8c9b5e",
                "f7f00702c3ca400b6adacc6de96779a48881fd7c3f544f95f99ac1037f6b9f49",
                "c308aed1f6634afcbd46dd6fcecc015fccc24716cc590687fb2492c96812c9ac",
                "037f743e3b47d60420ee271331031d290fa6179178444256acb5697fbcbfbbb4",
                "fd3c6227566de99b246a8914721d5dbe58c2411df01348b63bce4e3659ae7ad0",
                "9579be43acadad01ba02eb4c118b23ef64b318c7424920c5da7176ab2cdadb84",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_3,
            msg: concat!(
                "196c5dfa45aa9b9d8c8f0459ae650aeb45f1b05e06a6ecda44194fbdb5b5e7ec",
                "79b0656c583d7b2c4c0488253fcf77a51586e4e8ed5d81e9a44cb9779bc0938b",
                "bb90d8d9b63278a58f2f2ad85cd453534b2a2983e32918368c2965ad529911f2",
                "e6f3006ce5ef5ab05df8329a8edc659dedc7c5576f72776803989a8560aa29c8",
            ),
            sig: concat!(
                "4bfeb7f6d376548f1ada66742eb2320689db85eaca0f75845aff7cbc91faeb1e",
                "fe96ddaeabf8f9bf2b3031aff3711ebf9e4bbfd46861a8bb5107aea784a78205",
                "e067779e98be0a74458c0c850903f58dd3541636c2160a8854914798310324f8",
                "52c3806f0a0e59ac6b5d3ccfd2580443d09752640e27f41b1e692b3ffec67c39",
                "868f4605230b341a2b56ac68bd2fa3450df2ebf4867ac0156be6513e03bab686",
                "f435c931532632adc177e95971bfad056424230943e5757d0c5384671592b7b0",
                "bd4a454d4d73bf312f4f46f2f310e897bb657be3165d040ff0d8bf72315ae313",
                "fda1052c37307a31c2f8d4edce4644b5bfeb5ac37fdf0e2a393692dfb72bb4ea",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_3,
            msg: concat!(
                "c0b251836d180dbcb995b4ae6e18856be5e8bf067841b753394226efe507c780",
                "1312223eb1efa2b3b117eebe001676deb8e94cad96aa36abae6f013d5d6f18f6",
                "80665514e33b164efde094cdda7b707858c38f7496ac28ebaa461b0d92e28555",
                "6d78910eec45911503b84de0e48f9abf2d3e2f626090b59c95901d666baa3627",
            ),
            sig: concat!(
                "0cc0b5e4251083e72898e6d239dae55489a42675123fceb8abf34886846e5af3",
                "9d109fb65d55fb019c43c3fe91b891262d8ec0aa721acd97848f455f049d6af5",
                "8b5e579b92208fa48f7afcb403dd99870bb25a15b33a67b5a1ad10ccf3df04fb",
                "f5fc42a2a0dea7b6c689d18da14757b2b5ebeafc39f62b5fdbe58f44f03e148d",
                "4e5ae6ce1bdce9f316daf7722ba6622ea6eb964fc3d0d9ab54ac226a3371ef96",
                "300d9d737767cbd04963015781d14d9f0f640b1981219d391ae1d94eab184d68",
                "f1764e7dc2aa2890b08c16ac277aab85e2912975702ca0834ff7026be694f805",
                "fb2692a605635a020018342dd89b8a53f8b5fc7b5fa8b13fbd9f8b5deebbc199",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_3,
            msg: concat!(
                "9df2b3e0f8035d92193f0c980e8ce31aaf7218078171f907da982db246533dff",
                "2a8553ffa7d641cbc14fc4bbc1240ad8d7d07394046795b9372882a0b7524da3",
                "c03acad4719996f0e62a578ea175459c2ee5ea0c062125cbb59975f3385f7441",
                "a939a2c91ef464e8cefb4d7b75289b4efad905d84f47b4259a138f139222bbc1",
            ),
            sig: concat!(
                "a82261947dd0f5b3f34197bb91401278dca36b759a7402ae65d8db6b6a12fb2b",
                "cf67e564d16030fd1b7e4e4df9bf0577c5dd5d6a5d8766009277003d0e792967",
                "5ccdfa04285e74ecfa1a937db117a130fe4662da0a869d7d34832165f86ad8c3",
                "45cd6aa027036d818af45fcc8fb7bf55975c948af26ca363ff796c752afafc8e",
                "5afc5ce5208bacdaa98601046e69e648975a87ea34b011237bfe5f734d9470bf",
                "e71cd5053e2831d321fdb13e2a4221f992670782b7c584634761b7b96a28e33b",
                "69eba97ceb45aa1adffb29fd4705e4532e0fe1890d1575b5e43d4aa294c27936",
                "999b413a3086b000050330178b0f71248a0a92af444d8fcdaa0237b7952602a5",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_1,
            msg: concat!(
                "3f3544b53b09a91b7f1a27d5fed879788432e604a8b6d121fcf98ba886396b65",
                "7441211c0b8d47c9e1af392c4cf127851a3c689d823811055bb5c7a28c4ad16a",
                "c43b71686ba07506d8c4098bc4cccfe3fe99329f61eff73c04d614a8b040c602",
                "97eddea1428c5b59cc233ef94eb09a189a11eb122c21a84d5d241cc1da6571b7",
            ),
            sig: concat!(
                "8caf5231442d5352259da89fbf54888cd32774b7851232b21defd3ae6d780a53",
                "87ec021f0260cd299ced9fd814208d1102620cee37b2d48b5c9ad90c061f0c2a",
                "527bbd1eabd7aa76a5f4e083483eff1a9b5d62dfe57c751d9bc4999148556914",
                "2c65656a67213c37907db465dc7225c7fcdd7b9a37e3d6b887b07c3dd07dfcbd",
                "de86baccbdf6fd13676e062f9f875f912058536fbd31d4dafd9c051bb79236e6",
                "e0f90db221acfae0690b6fcba1cd7716145afabd39866e393dad2ae99b24f9d9",
                "7682e6c1163f5f442c4e49c7422923625b63e82fb1a3186fcf0bb81ba38d6761",
                "156b1f723c0de7fdbb0c678effc49c128e655f36ea465d41e704ad1b449294ef",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_3,
            msg: concat!(
                "2726543e530ab04b06a11cbae1da53aa966dc51642d390fcfe95acbfb0ca65cb",
                "28db0f77688af52f423392d2295104594143bdbab8517c0b59ea7beb5e2fea1e",
                "86b69d77688702fb076b5543a6671722de83bc88edcfa4a651a84c539638c6af",
                "6c3c6606fc0abff77cd2cdd50124744d95b229498a58f0150e5986c0ffecdfc6",
            ),
            sig: concat!(
                "51d57b3e66fd6e271241215438be99969c40d0ea4a5b7c4918143f68f58e5cd9",
                "d52d90159e7bdc9b73ac3d3d908cdda5e402f0fd352931f9bca9dd886fed30c7",
                "91efd2466dfc7c6483aa32c2865cef82a40dcf5c5bc3aad547b8e1dc9d973c8b",
                "90f529ef272a24645a6b76887925b6e19970d9f2d7d68a513f2e1638b184aa8c",
                "d20967618d06662bfe1450f03b72d19790fd1a591694043b310d982077285dea",
                "fc28f95b3c6218edf59649b38e9170fb3f18483fb3788a14b161648beb4ce471",
                "c0ba4c041b87e6b38067fb934f50908b755bd126d2904b75ad7ce75a8a5d0c35",
                "40e1d9c7ad52242f2e5a5511d46ad8099f9386299f369e69e53107c6f51fb985",
            ),
            valid: true,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_4,
            msg: concat!(
                "16ae604b3a4e9c7f1d616e2deab96b6207705b9a8f87468503cdd20a3c02cc8d",
                "a43d046da68b5ed163d926a5a714a4df1b8ef007bca408f68b9e20de86d6398a",
                "d81df5e74d5aaac40874b5d6787211ff88e128cf1676e84ca7f51aee5951efee",
                "1915dcc11502a8df74fac4c8451dda49b631a8fb87470f0ebe9b67449bbd1640",
            ),
            sig: concat!(
                "3a0751f873595e6c75cfe668304ce23e37da8f2412bef538256db7333562cd7b",
                "7457506912e176b8af543d5e01eb9742c8a42d356453a9d2ea9b78d6774144e3",
                "237e8fb3c0822c16a5550cc8dfb52af497df73d30643b4a8abe07c8e04cb1659",
                "09e030faffa2429089ab6ca3d88584a0669e4955334ad5c7d41bc5efcb901f7c",
                "afe0e31552da57833d595fcf955247545cd057781d58f27c9c1a835f19f40dee",
                "d90628de42de3b3efa4ad1a7311e67ee3354f6234e7aace3d39751a84611ff53",
                "d3ba70a552a78c74094c84cd401eab240aa33bf9c1492d1e173750f7505966ce",
                "83fcaae886102cd139f827386ff3898e7a1fcdde095cd96165a11b47ad5a43ca",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_4,
            msg: concat!(
                "b3d09ef22d893ef3cc09eaa9b2777e982a84341ceaa00d45956f73e484761ce6",
                "c61b31e165ccb0edeb7e0fb5255922ce27b13e4790399f8110730740276ba803",
                "2fa544919c5493d583cce5eb593a087bfe936c46f9ca85fe0646715bce93db6b",
                "f5581f2a5989ae5299ddb574d583f948b5110542adbd88657fcff95c01567cc7",
            ),
            sig: concat!(
                "859c4b66e9843f82baf341875b80215e16acedea013b10511a993b8407d72bd5",
                "dd00589d4016dde5b082f8cb0fee5f339d3e4167ba2399269e215afca6ec2c1e",
                "c3d572e214f9513086d281a4ccb5890d75bab00eb4bccc44074de6fef0e8c212",
                "37f7630557374da6779889016709aec7fe8c2999d14cfdd9a617bf858c941674",
                "737cf0723f146759e4aa691f4bad8af3296027f92fbb81476587f76759592cdc",
                "389a34d06d2bdab0bc87742e0013a11b571b58cc4990828d374268995b34d7eb",
                "8c09928efe0204cc349c83f575ff70ff3d4ffc9026561ce0601f17c8cdc945a5",
                "9b44d8323a8c3dcded6158e880c7e1a214c2d3554e814a0b9c64f35724261452",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_4,
            msg: concat!(
                "f41491a2448f0abab25b9f4958b6eb93343282e62dae1d2e5485f7c369057685",
                "a1230e2ba66c63d8e03fadeff33a612989f20ee551e784bf48b73c633791f4a4",
                "7ced9ac80e7a6b26bc585cf4b588b95a4da10ccafec44094add106b52fdb78f0",
                "0cdafc2183a06ccdce0f74fda7883b4d0aa645403d2d98d60e3d1d615ccc4a94",
            ),
            sig: concat!(
                "81007a0eaaab1b6205fb5579a55d50a7d7b4bb077eb0cdad18756b4bddc447cc",
                "6f1a427cfa32100cf5c0c00db6d28c371059e6341d947d843722ae8fcd0c81a4",
                "650fb96857ca5d09a270cbec62a2fcbf997b67fbae0763a5cc28f526c452b416",
                "f25fdca7bbaa82c966e7be2a5b0866da58b05e024439f15428b0815117efb9c0",
                "8310e193e7e7a5f2371f7c2c2edd17616a7fb991c2e173b7fd80ae4537d38ed6",
                "47c32dd16129e56600d32418575c608f360368b750faac157a3a43ff665a5ed5",
                "c545e07f413e9475e7d79d542356358f0c554cc206c3880406447308d1e0d187",
                "1d90a84ee4a43152488acbbeb7bf55fadaf3e8b32e01a363ca8e3935efda1e43",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_5,
            msg: concat!(
                "7cf8f94a517da2e5f856e8ddec29ab25a1a3b1faaf0eeb193326f92e7228ef8f",
                "c02d5a2aa1b67ebd2d88e245b9ba0fb8b30c94f6ce7a4dfd5f11e55d07029aed",
                "93f540bb209f8949839783f6e86562bab8dc8016c1aba24b912e7dcb228a79ed",
                "bdf8b4e418614af2c22cd4d9c0542e9379bd7e42cfc8716a8f25c85e0be814f8",
            ),
            sig: concat!(
                "636d180a954780e947e916eabfcd4cfce80dc0cba1cae58342e142207fee42f3",
                "f6655ffb6c78f89fe1d2f31ed54e991d14b814583e8c84723263a22734acadfb",
                "5bf00dcd6df8bda4ebb3927a36b13bca2991094f1f92610dcaf953b33a4d1cf5",
                "71085e297e3cca697e4aec953ab2134e23e62d176ade623e3e2efa562e7e0a87",
                "fb7ddc3a169325cd01fee10b2f6ed2012b9c9db99089521d2d15a15da86fcb16",
                "5501eaf454bb36c8798e0476f59bf2a7d5eb395228744e266198032de0afe58c",
                "b10f81dadf57dfad47f764721e54f1248c00f98d7fd2fbbc5aa0998b8a480a73",
                "df7c2eff9940bbf644cc821ffa9bf570f2b24c43570b81c103cb4d0c39deb507",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_4,
            msg: concat!(
                "7ff7ba5d5e8aa7de3ffc560672a9c1b0f2eee1c39a8d7fb89553475617f81ec0",
                "4a46b5b28c7d5e08d7f71f80800805c02528bb9be1545b90c1b184937c73ad11",
                "5efdb92e8649cb51518b5be216118a52146eb25ca8d7428bc4cdc9fd9cfd5066",
                "a264ed57b5b695c1950132b59b8df56da708ee9059dfdab284ef3c1adf5dafc9",
            ),
            sig: concat!(
                "55fd6153dfbdd9850218c3b48a4f5e74e9aea999b7e0bf0514481f29b9491d62",
                "a4a4dbae2fbaea27cd4dea5ddfc17052d3598bc329eb3ec437d1001387510d7d",
                "0288cfe298cc5fd9f7b91c887d41d81d6685853285d67e874467c036d52be31e",
                "e49bfcaaee129a3cda168b59ffe523ef64f7e972cbda2afedf1a0fe7c6d457d7",
                "9d9a73b7424fe6ec4290988dd81daa58e1fed69ddec52f8482a27da34b70114c",
                "d07f04591c5d2a38eefba0abd33d4c1f500a4073eafc5199548d7b96c772cac7",
                "1cc02e18fa998f143132bcfa5e44f2dd62692c90e9a96b243ee20310fa9fff79",
                "0b04a2d8811b46c5c97e66dbd5e36b03aa290cb9ae27ba94018e61430eac223f",
            ),
            valid: false,
        },
        Case {
            source: "SigVer15_186-3.rsp",
            key: &KEY_4,
            msg: concat!(
                "3b9ffc79b59b069fb97124a6c13d51ad413638c1e8e09dab2383f90be4db64ab",
                "a111b80d9feaf446703fde0fbbaded1a3b8d65a20a26c44620225d17163f43f0",
                "304768069b4206bff3ea3ec8095f0062e21c2afc032af407eb938b06e21afce4",
                "f129548b320b05b24a5b8cf633bd512d3fcccff75953f4958ebfcbffcdd45830",
            ),
            sig: concat!(
                "7f2efdaf79621804a71b9fda74328b00a65d949b26f739e1b9755ac860c5ad7b",
                "f63453a572fc54d6ec790230ac91a150ec428c252f2f8e222625b3e3e65e5abe",
                "5155b55da30fc2a89e22101f15a841058ccadfcaddb5405738d86fbbc85d8206",
                "2dc988a945fb2afb9a9c4d52494f0cfad39f120577931632c31a63f06a370d11",
                "50aa4a45441bb31ccab8f7f742f5419a14a302ee0c558de496c66002a0226615",
                "4ddf2b5808e33b920493e5db1719c9e6f7f43a069455024364988ad622d8d61a",
                "5b798a5f9849cf29a0d59eff8459ca65dfd0ea1a9381e8f595ff72d59bd86eb0",
                "4afe1c4b61c239a746eb102effa940c011321dec7675d99ec4d03261ac254602",
            ),
            valid: true,
        },
    ];

    #[test]
    fn cavp_rsa_pkcs1_sha1_2048() {
        assert_eq!(CASES.len(), 28);
        let mut valid = 0usize;
        for (i, case) in CASES.iter().enumerate() {
            let msg = hex::decode(case.msg).unwrap();
            let sig = hex::decode(case.sig).unwrap();
            let pkcs1 = pkcs1(case.key);
            let spki = spki(case.key);
            for encoding in
                [RsaPublicKeyEncoding::Pkcs1Der(&pkcs1), RsaPublicKeyEncoding::SpkiDer(&spki)]
            {
                assert_eq!(
                    verify_rsa_pkcs1_sha1(encoding, &msg, &sig),
                    Ok(case.valid),
                    "{} case {i} via {encoding:?}",
                    case.source
                );
            }
            if case.valid {
                valid += 1;
                // The same signature over a different message must fail.
                let mut other = msg.clone();
                other[0] ^= 0x01;
                assert_eq!(
                    verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&pkcs1), &other, &sig),
                    Ok(false)
                );
            }
        }
        assert_eq!(valid, 13);
    }

    #[test]
    fn cavp_1024_bit_key_is_refused() {
        // `[mod = 1024]` key from SigGen15_186-2.txt: below the 2048-bit floor.
        let key = Key {
            n: concat!(
                "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e2466304",
                "8441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53",
                "f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32a",
                "b57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991",
            ),
            e: "10001",
        };
        let der = pkcs1(&key);
        assert_eq!(
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(&der), b"m", &[0u8; 128]),
            Err(RsaLegacyError::UnsupportedKeySize { bits: 1024 })
        );
    }
}
