import { getElement } from './utils.ts';
import { renderError } from './ui.ts';

interface WasmModule {
    readonly default: () => Promise<void>;
    readonly rsa_demo_text: (text: string, p: string, q: string) => string;
    readonly rsa_demo_number: (message: string, p: string, q: string) => string;
    readonly validate_prime: (n: string) => boolean;
    readonly sha256_demo_text: (text: string) => string;
    readonly sha256_demo_bytes: (bytes: Uint8Array) => string;
    readonly ecc_demo_secp256k1: (private_key_hex: string) => string;
    readonly ecc_demo_weierstrass: (k: string, a: string, b: string, p: string, gx: string, gy: string) => string;
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

export const eccDemoSecp256k1 = (privateKeyHex: string): string => wasmState.get().ecc_demo_secp256k1(privateKeyHex);

export const eccDemoWeierstrass = (k: string, a: string, b: string, p: string, gx: string, gy: string): string =>
    wasmState.get().ecc_demo_weierstrass(k, a, b, p, gx, gy);

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

