import {scrypt} from "node:crypto";
import crypto from "crypto";

const defaultAlgorithm = "aes-256-gcm";

/*rejects on error*/
async function GetStretchedKey(/*BinaryLike*/key,/*BinaryLike*/salt,/*number*/keylen){
	return new Promise(async (resolve,reject) => {
		scrypt(key,salt,keylen,(err,derived_key) => {
			if (err || derived_key === undefined){
				return reject("Error deriving key using scrypt");
			}
			return resolve(derived_key);
		});
	});
}

async function GetBinaryBufferedKey(key){
	if (Buffer.isBuffer(key)){
		return key;
	}
	else
	{
		console.log('else hit');
		return Buffer.from(key, "binary");
	}
}

/*returns the encrypted data in hexadecimal format as a string from the provided data, key and cipher algorithm<br>
 * if the cipher algorithm is undefined it will default to aes-256-gcm<br>
* first 32 chars is the salt for password stretching (hex format), next 32 chars is the iv for AES encrypted data (hex formar)<br>
* next 32 chars (hex format) is the cipher auth and the rest is the AES encrypted data<br>
* salt and iv are stored in plain text<br>
* throws on error or invalid key type, can be of type*/
export async function EncryptData(/*String*/data, /*BinaryLike*/key, /*String*/ algorithm){
	key = await GetBinaryBufferedKey(key);
	if (algorithm === undefined){
		algorithm = defaultAlgorithm;
	}
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
	const derived_key = await GetStretchedKey(key, salt, 32);

    const cipher = crypto.createCipheriv("aes-256-gcm",derived_key,iv, {authTagLength:16});
    let encrypted_data = cipher.update(data, "utf-8","hex");
    encrypted_data += cipher.final("hex");
    const cipher_auth = cipher.getAuthTag().toString("hex");

    if (encrypted_data === undefined || cipher_auth === undefined){
        throw new Error("failed to get encrypted data");
    }

    // resolve with the salt + iv + auth + data (all in hex)
    return salt.toString("hex")+iv.toString("hex")+cipher_auth+encrypted_data;
}

/*Decrypts Data that was encrypted using the EncryptData function using the provided key and algorithm<br>
 * if algorithm is undefined it will default to aes-256-gcm<br>
 * returns undefined on decryption failure<br>
 * Will throw if called with data shorter then 96 or if key deriviation fails*/
export async function DecryptData(/*String*/encrypted_data, /*BinaryLike*/key){
	key = await GetBinaryBufferedKey(key);
	if (algorithm === undefined){
		algorithm = defaultAlgorithm;
	}
    // check if data can even contain the salt, iv and hash
    if (encrypted_data === undefined || encrypted_data.Length < 32 + 32 + 32){
        throw new Error("encrypted data is too short to contain salt iv and hash or its undefined...");
    }
    const salt = Buffer.from(encrypted_data.substring(0,32), "hex");
    const iv = Buffer.from(encrypted_data.substring(32,64),"hex");
    const authTag = Buffer.from(encrypted_data.substring(64,96), "hex");
    const acutalEncryptedData = encrypted_data.substring(96);
	const derived_key = await GetStretchedKey(key, salt, 32);

    const decipher = crypto.createDecipheriv(algorithm,derived_key,iv,{authTagLength:16});
    decipher.setAuthTag(authTag);
    try{
        let decrypted_data = decipher.update(acutalEncryptedData,"hex","utf-8");
        decrypted_data += decipher.final("utf-8");
        return resolve(decrypted_data);
    }
    catch (err){
		return undefined;
    }
}
