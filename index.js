import {scrypt} from "node:crypto";
import crypto from "crypto";

const defaultAlgorithm = "aes-256-gcm";
const defaultAlgorithmKeyBytes = 32;
const defaultAlgorithmIvLength = 16;
const defaultDataEncoding = undefined;
const defaultOuputEncoding = "utf8";
const saltLength = 16;
const authTagLength = 16;

export class DataCrypter{
	/*if algorithm is provided algorithmKeyBytesLength must also be provided, defaults to aes-256-gcm
	 * OutputEncoding defaults to utf8, DataEncoding defaults to undefined,iv defaults to 16*/
	constructor(/*String*/algorithm, /*Number*/algorithmKeyBytesLength, /*Number*/algorithmIvLength, /*String*/OutputEncoding, /*String*/DataEncoding){
		if (algorithm !== undefined){
			if (algorithmKeyBytesLength === undefined){
				throw new Error("Can't use custom algoirthm with undefined key bytes");
			}
			if (algorithmIvLength === undefined){
				throw new Error("Can't use custom algoirthm with undefined iv");
			}
			if (!crypto.getCiphers().includes(algorithm)){
				throw new Error("Unsupported algorithm");
			}
			this.algorithm = algorithm;
			this.algorithmKeyBytesLength = algorithmKeyBytesLength;
			this.algorithmIvLength = algorithmIvLength;
		}
		else{
			this.algorithm = defaultAlgorithm;
			this.algorithmKeyBytesLength = defaultAlgorithmKeyBytes;
			this.algorithmIvLength = defaultAlgorithmIvLength;
		}
		this.OutputEncoding = OutputEncoding === undefined ? defaultOuputEncoding : OutputEncoding;
		this.DataEncoding = DataEncoding === undefined ? defaultDataEncoding : DataEncoding;
	}

	/*Encrypts the provided data with key, returns the data as a buffer if DataEncoding is not set, else it returns it as a string using the DataEncoding<br>
	 * Attempts to get a buffer from data and key if they are not a buffer, make sure they can be input into Buffer.from, see <link>https://nodejs.org/api/buffer.html#static-method-bufferfromarray</link>*/
	EncryptData = async function(/*Buffer*/data, /*Buffer*/key){
		if (!Buffer.isBuffer(data)){
			data = Buffer.from(data);
		}
		if (!Buffer.isBuffer(key)){
			key = Buffer.from(key);
		}
    	const salt = crypto.randomBytes(saltLength);
    	const iv = crypto.randomBytes(this.algorithmIvLength);
		const derived_key = await GetStretchedKey(key, salt, this.algorithmKeyBytesLength);
	
    	const cipher = crypto.createCipheriv(this.algorithm,derived_key,iv, {authTagLength:authTagLength});
		const encryptedData = cipher.update(data);
		const encryptedDataFinal = cipher.final();
    	const cipher_auth = cipher.getAuthTag();

		const encrypted = Buffer.concat([salt,iv,cipher_auth,encryptedData,encryptedDataFinal]);
		return this.DataEncoding === undefined ? encrypted : encrypted.toString(this.DataEncoding);
	}

	/*Decrypts the provided data with the key, returns the datat as a buffer if OutputEncoding is not set, else it returns a string using OutputEncoding<br>
	 * If inputEncoding is set it will use that to get a Buffer.from(data,inputEncoding).<br>
	 * returns undefined if the decryption fails*/
	DecryptData = async function(/*object*/encryptedData, /*Buffer*/key){
		if (this.DataEncoding !== undefined){
			encryptedData = Buffer.from(encryptedData,this.DataEncoding);
		}
		else if (Buffer.isBuffer(encryptedData)){
			encryptedData = Buffer.from(encryptedData);
		}
		if (!Buffer.isBuffer(key)){
			key = Buffer.from(key);
		}
		if (encryptedData.length < saltLength + this.algorithmIvLength + authTagLength){
			throw new Error("provided data to short to be valid");
		}
    	const salt = encryptedData.subarray(0,saltLength); 
    	const iv = encryptedData.subarray(saltLength,saltLength+this.algorithmIvLength);
    	const authTag = encryptedData.subarray(saltLength+this.algorithmIvLength,saltLength+this.algorithmIvLength+authTagLength);

    	const acutalEncryptedData = encryptedData.subarray(saltLength+this.algorithmIvLength+authTagLength);
		const derived_key = await GetStretchedKey(key, salt, this.algorithmKeyBytesLength);
	
    	const decipher = crypto.createDecipheriv(this.algorithm,derived_key,iv,{authTagLength:authTagLength});
    	decipher.setAuthTag(authTag);
    	try{
			const decrypted = Buffer.concat([decipher.update(acutalEncryptedData), decipher.final()]);
			return this.OutputEncoding === undefined ? decrypted : decrypted.toString(this.OutputEncoding);
    	}
    	catch (err){
			return undefined;
    	}
	}
}


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
