import { initWasm as initWasmModule, isWasmReady, rsaDemoText, rsaDemoNumber, sha256DemoText, keccak256DemoText, eccDemoSecp256k1, eccDemoWeierstrass } from './wasm.ts';
import { renderRsaResults, renderSha256Results, renderKeccak256Results, renderWeierstrassResults, renderSecp256k1Results, renderError, renderLoading } from './ui.ts';
import type { RsaResult, Sha256Result, Keccak256Result, EccResult } from './ui.ts';
import { getElement, getTrimmedValue, getValue, isNumericString, validateNonEmpty, parseResult } from './utils.ts';
import type { ValidationResult, ParsedResult } from './utils.ts';

export { initWasmModule as initWasm };

interface RsaInputs {
    readonly message: string;
    readonly p: string;
    readonly q: string;
    readonly resultsDiv: HTMLElement | null;
}

interface WeierstrassInputs {
    readonly key: string;
    readonly a: string;
    readonly b: string;
    readonly p: string;
    readonly gx: string;
    readonly gy: string;
    readonly resultsDiv: HTMLElement | null;
}

interface Secp256k1Inputs {
    readonly key: string;
    readonly resultsDiv: HTMLElement | null;
}

interface Sha256Inputs {
    readonly message: string;
    readonly resultsDiv: HTMLElement | null;
}

interface Keccak256Inputs {
    readonly message: string;
    readonly resultsDiv: HTMLElement | null;
}

interface DemoConfig<TInputs, TResult> {
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
    for (const [name, val] of [['k', key], ['a', a], ['b', b], ['p', p], ['Gx', gx], ['Gy', gy]] as [string, string][]) {
        if (!val || !/^\d+$/.test(val)) return { valid: false, error: `${name} must be a non-negative integer` };
    }
    return { valid: true };
};

const validateSecp256k1Inputs = ({ key }: Secp256k1Inputs): ValidationResult => {
    const nonEmpty = validateNonEmpty(key, 'a private key');
    if (!nonEmpty.valid) return nonEmpty;
    if (!/^(0x)?[0-9a-fA-F]{1,64}$/.test(key)) {
        return { valid: false, error: 'secp256k1 private key must be a hex string (up to 64 chars)' };
    }
    return { valid: true };
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
