type WasmModule = {
    readonly default: () => Promise<void>;
    readonly blockchain_mine_block: (chain_json: string, data: string, hash_algo: string, difficulty: number, timestamp: number) => string;
};

type MineMessage = {
    readonly type: 'mine';
    readonly chainJson: string;
    readonly data: string;
    readonly algo: string;
    readonly difficulty: number;
};

let wasm: WasmModule | null = null;

const initWasm = async (): Promise<void> => {
    if (wasm) return;
    const mod = await import('../pkg/encryption_demo.js') as unknown as WasmModule;
    await mod.default();
    wasm = mod;
};

self.onmessage = async (e: MessageEvent<MineMessage>): Promise<void> => {
    const { type, chainJson, data, algo, difficulty } = e.data;
    if (type !== 'mine') return;

    try {
        await initWasm();
        const result = wasm!.blockchain_mine_block(chainJson, data, algo, difficulty, Date.now());
        self.postMessage({ type: 'result', result });
    } catch (err) {
        self.postMessage({ type: 'error', message: err instanceof Error ? err.message : 'Worker error' });
    }
};
