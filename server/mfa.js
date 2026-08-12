const crypto = require("crypto");
const { generateSecret, generateURI, verifySync } = require("otplib");

const normalizeToken = (value) => String(value || "").replace(/\D/g, "").slice(0, 6);
const normalizeRecoveryCode = (value) => String(value || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "");

const createMfaSecurity = ({ encryptionSecret, issuer = "Everkind Home Care" }) => {
    const getKey = () => {
        if (!encryptionSecret) {
            const error = new Error("MFA_ENCRYPTION_KEY must be configured before authenticator MFA can be used.");
            error.code = "MFA_ENCRYPTION_KEY_REQUIRED";
            throw error;
        }
        return crypto.createHash("sha256").update(String(encryptionSecret)).digest();
    };

    const encryptSecret = (plainText) => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", getKey(), iv);
        const encrypted = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
        return [iv, cipher.getAuthTag(), encrypted].map((value) => value.toString("base64url")).join(".");
    };

    const decryptSecret = (payload) => {
        const parts = String(payload || "").split(".");
        if (parts.length !== 3) throw new Error("Stored MFA secret is invalid.");
        const [iv, tag, encrypted] = parts.map((value) => Buffer.from(value, "base64url"));
        const decipher = crypto.createDecipheriv("aes-256-gcm", getKey(), iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
    };

    const hashValue = (purpose, value) =>
        crypto.createHmac("sha256", getKey()).update(`${purpose}:${String(value)}`).digest("hex");

    const verifyHash = (purpose, value, expectedHash) => {
        const actual = Buffer.from(hashValue(purpose, value), "hex");
        const expected = Buffer.from(String(expectedHash || ""), "hex");
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    };

    const createTotpSetup = (label) => {
        const secret = generateSecret({ length: 20 });
        return {
            secret,
            uri: generateURI({ issuer, label, secret, digits: 6, period: 30 }),
        };
    };

    const verifyTotp = (secret, token) => {
        const normalizedToken = normalizeToken(token);
        if (normalizedToken.length !== 6) return false;
        return Boolean(verifySync({
            secret,
            token: normalizedToken,
            digits: 6,
            period: 30,
            epochTolerance: 30,
        }).valid);
    };

    const createVerificationCode = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
    const createRecoveryCodes = (count = 10) => Array.from({ length: count }, () => {
        const raw = crypto.randomBytes(9).toString("base64url").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
        return raw.match(/.{1,4}/g).join("-");
    });

    return {
        createRecoveryCodes,
        createTotpSetup,
        createVerificationCode,
        decryptSecret,
        encryptSecret,
        hashChallenge: (nonce, code) => hashValue(`challenge:${nonce}`, normalizeToken(code)),
        hashRecoveryCode: (code) => hashValue("recovery", normalizeRecoveryCode(code)),
        normalizeRecoveryCode,
        normalizeToken,
        verifyChallenge: (nonce, code, hash) => verifyHash(`challenge:${nonce}`, normalizeToken(code), hash),
        verifyRecoveryCode: (code, hash) => verifyHash("recovery", normalizeRecoveryCode(code), hash),
        verifyTotp,
    };
};

const maskEmail = (email) => {
    const [local, domain] = String(email || "").split("@");
    if (!local || !domain) return "";
    return `${local.slice(0, 1)}${"*".repeat(Math.max(3, local.length - 1))}@${domain}`;
};

const maskPhone = (phone) => {
    const digits = String(phone || "").replace(/\D/g, "");
    if (!digits) return "";
    return `${"*".repeat(Math.max(6, digits.length - 4))}${digits.slice(-4)}`;
};

module.exports = { createMfaSecurity, maskEmail, maskPhone };
