import { DataCrypter } from "../index.js"
import * as crypto from "crypto"
import {fail} from "assert";

test("string inputs should work",async () => {
	try{
		const data = "test";
		const key = "key";
		const crypter = new DataCrypter(); 
		const encryptedData = await crypter.EncryptData(data,key);
		const decryptedData = await crypter.DecryptData(encryptedData,key);

		expect(decryptedData).toBe(data);
	}
	catch (ex){
		console.error(ex);
		fail();
	}
});

test("long string inputs should work",async() => {
	try{
		const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()".repeat(500);
		const key = "9*SDF(ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()".repeat(500);
		const crypter = new DataCrypter(); 
		const encryptedData = await crypter.EncryptData(data,key);
		const decryptedData = await crypter.DecryptData(encryptedData,key);

		expect(decryptedData).toBe(data);
	}
	catch (ex){
		console.error(ex);
		fail();
	}
});

test("buffer as inputs should work",async() => {
	try{
		const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()".repeat(50);
		const key = "9*SDF(ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()".repeat(5);
		const crypter = new DataCrypter(); 
		const encryptedData = await crypter.EncryptData(Buffer.from(data),Buffer.from(key));
		const decryptedData = await crypter.DecryptData(encryptedData,Buffer.from(key));

		expect(decryptedData).toBe(data);
	}
	catch (ex){
		console.error(ex);
		fail();
	}
});

test("numeric inputs should not work",async() => {
	try{
		const data = 500023;
		const key = 1040;
		const crypter = new DataCrypter(); 
		const encryptedData = await crypter.EncryptData(data,key);
		const decryptedData = await crypter.DecryptData(encryptedData,key);
		fail("test should've thrown");
	}
	catch (ex){
		expect(true);
	}
});

test("defined algorithm without key bytes should throw",async() =>{
	try{
		const data = "data";
		const key = "secret";
		const crypter = new DataCrypter("aes-256-gcm"); 
		const encryptedData = await crypter.EncryptData(data,key);
		const decryptedData = await crypter.DecryptData(encryptedData,key);
		fail("test should've thrown");
	}
	catch (ex){
		expect(true);
	}
});

test("defined algorithm with defined key bytes but without iv length should throw",async() =>{
	try{
		const data = "data";
		const key = "secret";
		const crypter = new DataCrypter("aes-256-gcm",32); 
		const encryptedData = await crypter.EncryptData(data,key);
		const decryptedData = await crypter.DecryptData(encryptedData,key);
		fail("test should've thrown");
	}
	catch (ex){
		expect(true);
	}
});

test("unsupported algorithm should throw",async() =>{
	try{
		const data = "data";
		const key = "secret";
		const crypter = new DataCrypter("ceaser",32,16,false); 
		const encryptedData = await crypter.EncryptData(data,key);
		const decryptedData = await crypter.DecryptData(encryptedData,key);
		fail("test should've thrown");
	}
	catch (ex){
		expect(true);
	}
});

testSpecificAlgorithm("chacha20-poly1305", 32, 12);
testSpecificAlgorithm();

function testSpecificAlgorithm(algoName, keyLen, ivLen){
	test(algoName + " algorithm should work",async() => {
		try{
			const data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()".repeat(50) + crypto.randomBytes(20).toString("utf8");
			const key = "9*SDF(ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%^&*()".repeat(5) + crypto.randomBytes(20).toString("utf8");
			const crypter = new DataCrypter(algoName,keyLen,ivLen); 
			const encryptedData = await crypter.EncryptData(data,key);
			const decryptedData = await crypter.DecryptData(encryptedData,key);
			expect(decryptedData).toBe(data);
		}
		catch (ex){
			console.error(ex);
			fail();
		}
	});
}



