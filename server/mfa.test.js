const assert = require("node:assert/strict");
const test = require("node:test");
const { generateSync } = require("otplib");

const { createMfaSecurity, maskEmail, maskPhone } = require("./mfa");

const mfa = createMfaSecurity({
    encryptionSecret: "test-only-encryption-key",
    issuer: "Everkind Test",
});

test("encrypts and decrypts authenticator secrets", () => {
    const encrypted = mfa.encryptSecret("JBSWY3DPEHPK3PXP");
    assert.notEqual(encrypted, "JBSWY3DPEHPK3PXP");
    assert.equal(mfa.decryptSecret(encrypted), "JBSWY3DPEHPK3PXP");
});

test("hashes verification and recovery codes without storing them", () => {
    const challengeHash = mfa.hashChallenge("nonce", "123456");
    assert.equal(mfa.verifyChallenge("nonce", "123456", challengeHash), true);
    assert.equal(mfa.verifyChallenge("nonce", "654321", challengeHash), false);

    const recoveryHash = mfa.hashRecoveryCode("ABCD-EFGH-IJKL");
    assert.equal(mfa.verifyRecoveryCode("abcd efgh ijkl", recoveryHash), true);
    assert.equal(mfa.verifyRecoveryCode("ZZZZ-EFGH-IJKL", recoveryHash), false);
});

test("generates standards-compatible TOTP setup", () => {
    const setup = mfa.createTotpSetup("admin@example.com");
    const token = generateSync({ secret: setup.secret, digits: 6, period: 30 });
    assert.match(setup.uri, /^otpauth:\/\/totp\//);
    assert.equal(mfa.verifyTotp(setup.secret, token), true);
});

test("masks contact destinations", () => {
    assert.equal(maskEmail("demo@everkind.ie"), "d***@everkind.ie");
    assert.equal(maskPhone("0851455244"), "******5244");
});
