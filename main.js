const bip39 = require("bip39");
const EC = require("elliptic").ec;
const crypto = require("crypto");

const ec = new EC("secp256k1");

const mnemonic = bip39.generateMnemonic();

const seed = bip39.mnemonicToEntropy(mnemonic)

const key = Buffer.from('Bitcoin seed', 'utf8');
const hmac = crypto.createHmac('sha512', key);

const hash = hmac.update(seed).digest();
const privateKey = hash.slice(0, 32);

console.log(privateKey.toString('hex'));

const another = ec.keyFromPrivate(privateKey.toString());

console.log(another.getPublic("hex"));