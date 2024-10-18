import { EncryptData, DecryptData} from "../index.js"
import * as crypto from "crypto"

test("Basic Input",() => {
	expect(EncryptData("abcdefg",crypto.randomBytes(10))).toBeDefined();
});
