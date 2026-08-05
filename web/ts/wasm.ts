import { getElement } from './utils.ts';
import { renderError } from './ui.ts';

interface WasmModule {
    readonly default: () => Promise<void>;
    readonly rsa_demo_text: (text: string, p: string, q: string) => string;
    readonly rsa_demo_number: (message: string, p: string, q: string) => string;
    readonly validate_prime: (n: string) => boolean;
    readonly sha256_demo_text: (text: string) => string;
    readonly sha256_demo_bytes: (bytes: Uint8Array) => string;
    readonly keccak256_demo_text: (text: string) => string;
    readonly ecc_demo_secp256k1: (private_key_hex: string) => string;
    readonly ecc_demo_weierstrass: (k: string, a: string, b: string, p: string, gx: string, gy: string) => string;
    readonly blockchain_create_genesis: (hash_algo: string, difficulty: number, timestamp: number) => string;
    readonly blockchain_mine_block: (chain_json: string, data: string, hash_algo: string, difficulty: number, timestamp: number) => string;
    readonly blockchain_validate: (chain_json: string) => string;
    readonly blockchain_tamper: (chain_json: string, block_index: number, new_data: string) => string;
    readonly ecdsa_sign: (private_key_hex: string, message: string) => string;
    readonly ecdsa_verify: (pubkey_x: string, pubkey_y: string, r: string, s: string, message: string) => string;
}

interface WasmState {
    readonly isReady: () => boolean;
    readonly get: () => WasmModule;
    readonly initialise: (module: WasmModule) => void;
}

const createWasmState = (): WasmState => {
    let module: WasmModule | undefined;
    return {
        isReady: () => module !== undefined,
        get: () => {
            if (!module) throw new Error('WASM not initialised');
            return module;
        },
        initialise: (wasm: WasmModule) => {
            if (module) throw new Error('WASM already initialised');
            module = wasm;
        }
    };
};

const wasmState = createWasmState();

export const isWasmReady = (): boolean => wasmState.isReady();

export const rsaDemoText = (text: string, p: string, q: string): string => wasmState.get().rsa_demo_text(text, p, q);

export const rsaDemoNumber = (message: string, p: string, q: string): string => wasmState.get().rsa_demo_number(message, p, q);

export const sha256DemoText = (text: string): string => wasmState.get().sha256_demo_text(text);

export const sha256DemoBytes = (bytes: Uint8Array): string => wasmState.get().sha256_demo_bytes(bytes);

export const keccak256DemoText = (text: string): string => wasmState.get().keccak256_demo_text(text);

export const eccDemoSecp256k1 = (privateKeyHex: string): string => wasmState.get().ecc_demo_secp256k1(privateKeyHex);

export const eccDemoWeierstrass = (k: string, a: string, b: string, p: string, gx: string, gy: string): string =>
    wasmState.get().ecc_demo_weierstrass(k, a, b, p, gx, gy);

export const blockchainCreateGenesis = (hashAlgo: string, difficulty: number): string =>
    wasmState.get().blockchain_create_genesis(hashAlgo, difficulty, Date.now());

export const blockchainMineBlock = (chainJson: string, data: string, hashAlgo: string, difficulty: number): string =>
    wasmState.get().blockchain_mine_block(chainJson, data, hashAlgo, difficulty, Date.now());

export const blockchainValidate = (chainJson: string): string =>
    wasmState.get().blockchain_validate(chainJson);

export const blockchainTamper = (chainJson: string, blockIndex: number, newData: string): string =>
    wasmState.get().blockchain_tamper(chainJson, blockIndex, newData);

export const ecdsaSign = (privateKeyHex: string, message: string): string =>
    wasmState.get().ecdsa_sign(privateKeyHex, message);

export const ecdsaVerify = (pubkeyX: string, pubkeyY: string, r: string, s: string, message: string): string =>
    wasmState.get().ecdsa_verify(pubkeyX, pubkeyY, r, s, message);

export const initWasm = async (): Promise<boolean> => {
    try {
        const wasm = await import('../pkg/encryption_demo.js') as unknown as WasmModule;
        await wasm.default();
        wasmState.initialise(wasm);
        console.log('WASM loaded successfully!');
        return true;
    } catch (e) {
        console.error('Failed to load WASM:', e);
        const resultsDiv = getElement('rsa-results');
        if (resultsDiv) {
            renderError(resultsDiv, 'Failed to load WebAssembly module. Make sure you\'re running this from a web server.');
        }
        return false;
    }
};

