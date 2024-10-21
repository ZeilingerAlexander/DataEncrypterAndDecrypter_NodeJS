import exp from "constants";
import { EncryptData, DecryptData} from "../index.js"
import * as crypto from "crypto"
import {fail} from "assert";

test("Basic Input",async () => {
	try{
		expect(await EncryptData("abcdefg",crypto.randomBytes(10))).toBeDefined();
		expect(await EncryptData("KSA*DHJA",crypto.randomBytes(10))).toBeDefined();
		expect(await EncryptData("AS(D*J@UIOQAHDSOPA  Aa// //?||",crypto.randomBytes(10))).toBeDefined();
	}
	catch (ex){
		fail();
	}
	});

test("Invalid Inputs",async () => {
	try{
		await EncryptData(undefined,"");
		await EncryptData("");
		await EncryptData();
		fail();
	}
	catch(ex){
		expect(ex).toBeDefined();
	}
});

test("Long inputs", async () => {
	const data = "abcdefghijklmnopqrstuvwABCDEFGHIJKLMNOPQRSTUVW_@(!(#)(!#)@($!(*".repeat(5000);
	const data2 = data.repeat(99);
	try{
		expect(await EncryptData(data,crypto.randomBytes(99999))).toBeDefined();
		expect(await EncryptData(data2,crypto.randomBytes(99999999))).toBeDefined();
	}
	catch(ex){
		fail();
	}
});

function GetRandomString(length){
	if (length === undefined){
		length = 5000;
	}
	return crypto.randomBytes(length).toString("utf8");
}

test("Encryption and Decrytpion same string", async () => {
	const key = crypto.randomBytes(50);
	const key2 = crypto.randomBytes(223901);
	const data = GetRandomString();
	const data2 = GetRandomString();
	const data3 = GetRandomString();
	const data4 = GetRandomString();
	const encrypted = await EncryptData(data,key);
	const decrypted = await DecryptData(encrypted,key);
	const encrypted2 = await EncryptData(data2,key2);
	const decrypted2 = await DecryptData(encrypted2,key2);
	const encrypted3 = await EncryptData(data3,key);
	const decrypted3 = await DecryptData(encrypted3,key);
	const encrypted4 = await EncryptData(data4,key2);
	const decrypted4 = await DecryptData(encrypted4,key2);
	expect(decrypted).toBe(data);
	expect(decrypted2).toBe(data2);
	expect(decrypted3).toBe(data3);
	expect(decrypted4).toBe(data4);
});
