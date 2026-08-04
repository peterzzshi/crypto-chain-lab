// Type stub matching #[wasm_bindgen] exports in src/wasm/mod.rs — update together
export function rsa_demo_text(text: string, p: string, q: string): string;
export function rsa_demo_number(message: string, p: string, q: string): string;
export function validate_prime(n: string): boolean;
export function sha256_demo_text(text: string): string;
export function sha256_demo_bytes(bytes: Uint8Array): string;
export function ecc_demo_secp256k1(private_key_hex: string): string;
export function ecc_demo_weierstrass(k: string, a: string, b: string, p: string, gx: string, gy: string): string;
export default function init(): Promise<void>;
