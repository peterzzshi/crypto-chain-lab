import { initWasm as initWasmModule, isWasmReady, rsaDemoText, rsaDemoNumber, sha256DemoText, keccak256DemoText, eccDemoSecp256k1, eccDemoWeierstrass, ecdsaSign, ecdsaVerify } from './wasm.ts';
import { renderRsaResults, renderSha256Results, renderKeccak256Results, renderWeierstrassResults, renderSecp256k1Results, renderEcdsaSignResults, renderEcdsaVerifyResults, renderError, renderLoading } from './ui.ts';
import type { RsaResult, Sha256Result, Keccak256Result, EccResult, EcdsaSignResult, EcdsaVerifyResult } from './ui.ts';
import { getElement, getTrimmedValue, getValue, isNumericString, validateNonEmpty, parseResult } from './utils.ts';
import type { ValidationResult, ParsedResult } from './utils.ts';

export { initWasmModule as initWasm };

type RsaInputs = {
    readonly message: string;
    readonly p: string;
    readonly q: string;
    readonly resultsDiv: HTMLElement | null;
}

type WeierstrassInputs = {
    readonly key: string;
    readonly a: string;
    readonly b: string;
    readonly p: string;
    readonly gx: string;
    readonly gy: string;
    readonly resultsDiv: HTMLElement | null;
}

type Secp256k1Inputs = {
    readonly key: string;
    readonly resultsDiv: HTMLElement | null;
}

type EcdsaSignInputs = {
    readonly key: string;
    readonly message: string;
    readonly resultsDiv: HTMLElement | null;
}

type EcdsaVerifyInputs = {
    readonly pubkeyX: string;
    readonly pubkeyY: string;
    readonly r: string;
    readonly s: string;
    readonly message: string;
    readonly resultsDiv: HTMLElement | null;
}

type Sha256Inputs = {
    readonly message: string;
    readonly resultsDiv: HTMLElement | null;
}

type Keccak256Inputs = {
    readonly message: string;
    readonly resultsDiv: HTMLElement | null;
}

type DemoConfig<TInputs, TResult> = {
    readonly getInputs: () => TInputs;
    readonly validate: (inputs: TInputs) => ValidationResult;
    readonly compute: (inputs: TInputs) => ParsedResult<TResult>;
    readonly renderSuccess: (container: HTMLElement, result: TResult) => void;
    readonly loadingMessage: string;
}

const getRsaInputs = (): RsaInputs => ({
    message: getTrimmedValue('rsa-message'),
    p: getTrimmedValue('rsa-p'),
    q: getTrimmedValue('rsa-q'),
    resultsDiv: getElement('rsa-results'),
});

const getSha256Inputs = (): Sha256Inputs => ({
    message: getValue('sha256-message'),
    resultsDiv: getElement('sha256-results')
});

const getKeccak256Inputs = (): Keccak256Inputs => ({
    message: getValue('keccak256-message'),
    resultsDiv: getElement('keccak256-results'),
});

const getWeierstrassInputs = (): WeierstrassInputs => ({
    key: getTrimmedValue('weierstrass-key'),
    a: getTrimmedValue('weierstrass-a'),
    b: getTrimmedValue('weierstrass-b'),
    p: getTrimmedValue('weierstrass-p'),
    gx: getTrimmedValue('weierstrass-gx'),
    gy: getTrimmedValue('weierstrass-gy'),
    resultsDiv: getElement('weierstrass-results'),
});

const getSecp256k1Inputs = (): Secp256k1Inputs => ({
    key: getTrimmedValue('secp256k1-key'),
    resultsDiv: getElement('secp256k1-results'),
});

const getEcdsaSignInputs = (): EcdsaSignInputs => ({
    key: getTrimmedValue('secp256k1-key'),
    message: getTrimmedValue('ecdsa-message'),
    resultsDiv: getElement('ecdsa-results'),
});

const getEcdsaVerifyInputs = (): EcdsaVerifyInputs => ({
    pubkeyX: getTrimmedValue('ecdsa-verify-pubkey-x'),
    pubkeyY: getTrimmedValue('ecdsa-verify-pubkey-y'),
    r: getTrimmedValue('ecdsa-verify-r'),
    s: getTrimmedValue('ecdsa-verify-s'),
    message: getTrimmedValue('ecdsa-verify-message'),
    resultsDiv: getElement('ecdsa-verify-results'),
});

const validateRsaInputs = ({ message, p, q }: RsaInputs): ValidationResult => {
    const messageCheck = validateNonEmpty(message, 'a message');
    if (!messageCheck.valid) return messageCheck;
    if (!p || !/^\d+$/.test(p)) return { valid: false, error: 'p must be a positive integer (decimal or 0x hex)' };
    if (!q || !/^\d+$/.test(q)) return { valid: false, error: 'q must be a positive integer (decimal or 0x hex)' };
    return { valid: true };
};

const validateSha256Inputs = ({ message }: Sha256Inputs): ValidationResult =>
    validateNonEmpty(message, 'a message');

const validateKeccak256Inputs = ({ message }: Keccak256Inputs): ValidationResult =>
    validateNonEmpty(message, 'a message');

const validateWeierstrassInputs = ({ key, a, b, p, gx, gy }: WeierstrassInputs): ValidationResult => {
    const fields: [string, string][] = [['k', key], ['a', a], ['b', b], ['p', p], ['Gx', gx], ['Gy', gy]];
    const bad = fields.find(([, val]) => !val || !/^\d+$/.test(val));
    return bad ? { valid: false, error: `${bad[0]} must be a non-negative integer` } : { valid: true };
};

const validateSecp256k1Inputs = ({ key }: Secp256k1Inputs): ValidationResult => {
    const nonEmpty = validateNonEmpty(key, 'a private key');
    if (!nonEmpty.valid) return nonEmpty;
    if (!/^(0x)?[0-9a-fA-F]{1,64}$/.test(key)) {
        return { valid: false, error: 'secp256k1 private key must be a hex string (up to 64 chars)' };
    }
    return { valid: true };
};

const validateEcdsaSignInputs = ({ key, message }: EcdsaSignInputs): ValidationResult => {
    const keyCheck = validateSecp256k1Inputs({ key, resultsDiv: null });
    if (!keyCheck.valid) return keyCheck;
    return validateNonEmpty(message, 'a message to sign');
};

const isHex64 = (v: string): boolean => /^(0x)?[0-9a-fA-F]{1,64}$/.test(v);

const validateEcdsaVerifyInputs = ({ pubkeyX, pubkeyY, r, s, message }: EcdsaVerifyInputs): ValidationResult => {
    const fields: [string, string][] = [['Public key X', pubkeyX], ['Public key Y', pubkeyY], ['r', r], ['s', s]];
    const firstError = fields.reduce<ValidationResult | null>((err, [name, val]) => {
        if (err) return err;
        const ne = validateNonEmpty(val, name);
        if (!ne.valid) return ne;
        return isHex64(val) ? null : { valid: false, error: `${name} must be a hex string (up to 64 chars)` };
    }, null);
    if (firstError) return firstError;
    return validateNonEmpty(message, 'a message');
};

const computeRsa = (message: string, p: string, q: string): ParsedResult<RsaResult> => {
    const resultJson = isNumericString(message)
        ? rsaDemoNumber(message, p, q)
        : rsaDemoText(message, p, q);
    return parseResult<RsaResult>(resultJson);
};

const computeSha256 = (message: string): ParsedResult<Sha256Result> =>
    parseResult<Sha256Result>(sha256DemoText(message));

const computeKeccak256 = (message: string): ParsedResult<Keccak256Result> =>
    parseResult<Keccak256Result>(keccak256DemoText(message));

const computeWeierstrass = (key: string, a: string, b: string, p: string, gx: string, gy: string): ParsedResult<EccResult> =>
    parseResult<EccResult>(eccDemoWeierstrass(key, a, b, p, gx, gy));

const computeSecp256k1 = (key: string): ParsedResult<EccResult> =>
    parseResult<EccResult>(eccDemoSecp256k1(key));

const computeEcdsaSign = (key: string, message: string): ParsedResult<EcdsaSignResult> =>
    parseResult<EcdsaSignResult>(ecdsaSign(key, message));

const computeEcdsaVerify = (pubkeyX: string, pubkeyY: string, r: string, s: string, message: string): ParsedResult<EcdsaVerifyResult> =>
    parseResult<EcdsaVerifyResult>(ecdsaVerify(pubkeyX, pubkeyY, r, s, message));

const runDemo = async <TInputs extends { resultsDiv: HTMLElement | null }, TResult>({
    getInputs,
    validate,
    compute,
    renderSuccess,
    loadingMessage
}: DemoConfig<TInputs, TResult>): Promise<void> => {
    if (!isWasmReady()) return;

    const inputs = getInputs();
    const { resultsDiv } = inputs;

    if (!resultsDiv) {
        console.error('Results container not found');
        return;
    }

    const validation = validate(inputs);
    if (!validation.valid) {
        renderError(resultsDiv, validation.error);
        return;
    }

    renderLoading(resultsDiv, loadingMessage);

    try {
        const result = compute(inputs);
        if (!result.ok) {
            renderError(resultsDiv, result.error);
            return;
        }
        renderSuccess(resultsDiv, result.data);
    } catch (e) {
        console.error(e);
        renderError(resultsDiv, e instanceof Error ? e.message : 'An unknown error occurred');
    }
};

export const runRsaDemo = (): Promise<void> => runDemo<RsaInputs, RsaResult>({
    getInputs: getRsaInputs,
    validate: validateRsaInputs,
    compute: ({ message, p, q }) => computeRsa(message, p, q),
    renderSuccess: renderRsaResults,
    loadingMessage: 'Processing...'
});

export const runSha256Demo = (): Promise<void> => runDemo<Sha256Inputs, Sha256Result>({
    getInputs: getSha256Inputs,
    validate: validateSha256Inputs,
    compute: ({ message }) => computeSha256(message),
    renderSuccess: renderSha256Results,
    loadingMessage: 'Computing hash...'
});

export const runKeccak256Demo = (): Promise<void> => runDemo<Keccak256Inputs, Keccak256Result>({
    getInputs: getKeccak256Inputs,
    validate: validateKeccak256Inputs,
    compute: ({ message }) => computeKeccak256(message),
    renderSuccess: renderKeccak256Results,
    loadingMessage: 'Computing hash...'
});

export const runWeierstrassDemo = (): Promise<void> => runDemo<WeierstrassInputs, EccResult>({
    getInputs: getWeierstrassInputs,
    validate: validateWeierstrassInputs,
    compute: ({ key, a, b, p, gx, gy }) => computeWeierstrass(key, a, b, p, gx, gy),
    renderSuccess: renderWeierstrassResults,
    loadingMessage: 'Deriving public key...',
});

export const runSecp256k1Demo = (): Promise<void> => runDemo<Secp256k1Inputs, EccResult>({
    getInputs: getSecp256k1Inputs,
    validate: validateSecp256k1Inputs,
    compute: ({ key }) => computeSecp256k1(key),
    renderSuccess: renderSecp256k1Results,
    loadingMessage: 'Deriving public key...',
});

export const runEcdsaSignDemo = (): Promise<void> => runDemo<EcdsaSignInputs, EcdsaSignResult>({
    getInputs: getEcdsaSignInputs,
    validate: validateEcdsaSignInputs,
    compute: ({ key, message }) => computeEcdsaSign(key, message),
    renderSuccess: renderEcdsaSignResults,
    loadingMessage: 'Signing message...',
});

export const runEcdsaVerifyDemo = (): Promise<void> => runDemo<EcdsaVerifyInputs, EcdsaVerifyResult>({
    getInputs: getEcdsaVerifyInputs,
    validate: validateEcdsaVerifyInputs,
    compute: ({ pubkeyX, pubkeyY, r, s, message }) => computeEcdsaVerify(pubkeyX, pubkeyY, r, s, message),
    renderSuccess: renderEcdsaVerifyResults,
    loadingMessage: 'Verifying signature...',
});
