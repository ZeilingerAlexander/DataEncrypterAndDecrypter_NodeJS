# Data Encrypter and Decrypter 
Encrypts and decrypts data using scrypt for key deriviation and all availiable algorithms in <code>crypto.createCipherIv</code>, this is just a wrapper for the node crypto module which does all the heavy lifting

## Usage
Make sure the key is an object that can be interpreted as a buffer<br>
If the program fails to generate a buffer from the key it will throw<br>
The Default algorithm is aes-256-gcm<br>

```js
import { DataCrypter } from "basic-crypter"

const crypter = new DataCrypter();

const key = "test";
const data = "Very Secret Data";

const encrypted_data = await crypter.EncryptData(data,key);
const decrypted_data = await crypter.DecryptData(encrypted_data,key);

if (decrypted_data === data){
    console.log("Success!");
}
```

## Use a Different Algorithm
Currently only algorithms that are able to use auth tags are supported. If there is demand for it i will make it so others work as well [create a github issue](https://github.com/ZeilingerAlexander/DataEncrypterAndDecrypter_NodeJS/issues/new "github create new issue").<br>
If you attempt to use an algorithm that does not support auth tags it will throw. If you put in the wrong values for key size and iv size it will throw.
```js
import { DataCrypter } from "basic-crypter"

// algorithm, key size (bytes), iv size (bytes)
const crypter = new DataCrypter("chacha20-poly1305", 32, 12);

const key = "test";
const data = "Very Secret Data";

const encrypted_data = await crypter.EncryptData(data,key);
const decrypted_data = await crypter.DecryptData(encrypted_data,key);

if (decrypted_data === data){
    console.log("Success!");
}
```

## Encoding of input and output
By default the ouput of encryptData is a buffer and the output of decryptData is in utf8. Here is how you can change it.
```js
import { DataCrypter } from "basic-crypter"

// leave rest undefined to use default options 
// ascii is the output encoding and hex the data encoding to use on input to decrypt and output on encrypt
const crypter = new DataCrypter(undefined,undefined,undefined,"ascii","hex");

const key = "test";
const data = "Very Secret Data";

const encrypted_data = await crypter.EncryptData(data,key);
console.log(encrypted_data); // in hex
const decrypted_data = await crypter.DecryptData(encrypted_data,key);
console.log(decrypted_data); // in ascii

if (decrypted_data === data){
    console.log("Success!");
}
```

## Supported Algorithms
Depends on [node <code>crypto.createCipherIv()</code>](https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options "node js crypto library")<br>
The Algorithm must support [node <code>cipher.getAuthTag()</code>](https://nodejs.org/api/crypto.html#ciphergetauthtag "node js crypto library")<br>
If you are unsure if the algorithm is supported just try it out or use the default which should be fine for most use cases<br>
Run <code>openssl list -cipher-algorithms</code> in your terminal to see availiabe algorithms (this does not mean that they are supported)

## Source Code and License
See [github](https://github.com/ZeilingerAlexander/DataEncrypterAndDecrypter_NodeJS "github repo")
