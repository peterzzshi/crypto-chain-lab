import { isWasmReady, blockchainCreateGenesis, blockchainMineBlock, blockchainValidate, blockchainTamper } from './wasm.ts';
import { getElement } from './utils.ts';

type Block = {
    readonly index: number;
    readonly timestamp: number;
    readonly data: string;
    readonly previous_hash: string;
    readonly hash: string;
    readonly nonce: number;
    readonly difficulty: number;
    readonly hash_algo: string;
}

type Chain = {
    readonly blocks: Block[];
}

type MineStep = {
    readonly step_number: number;
    readonly title: string;
    readonly description: string;
    readonly data: readonly string[];
}

type MineBlockResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly chain?: Chain;
    readonly steps: readonly MineStep[];
    readonly attempts: number;
}

type ChainResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly chain?: Chain;
}

type ValidateResult = {
    readonly valid: boolean;
    readonly error?: string;
    readonly invalid_block_index?: number;
    readonly message: string;
}

let chainState: Chain | null = null;
let savedChains: ReadonlyArray<Chain> = [];

const getHashAlgo = (): string =>
    (getElement('blockchain-algo') as HTMLSelectElement)?.value ?? 'sha256';

const getDifficulty = (): number =>
    parseInt((getElement('blockchain-difficulty') as HTMLInputElement)?.value ?? '2', 10);

const setMineSection = (visible: boolean): void => {
    const el = getElement('blockchain-mine-section');
    if (el) el.style.display = visible ? 'block' : 'none';
};

const setStatus = (message: string, valid: boolean | null): void => {
    const el = getElement('blockchain-status');
    if (!el) return;
    el.textContent = message;
    el.className = 'blockchain-status ' + (valid === null ? 'status-neutral' : valid ? 'status-valid' : 'status-invalid');
};

const fmtTimestamp = (ts: number): string => new Date(ts).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

const renderBlockCard = (block: Block, isInvalid: boolean): string => {
    const algoLabel = block.hash_algo === 'keccak256' ? 'Keccak-256' : 'SHA-256';
    const border = isInvalid ? '#ef4444' : '#22c55e';
    const badge = isInvalid ? '<span style="color:#ef4444;float:right">✗ tampered</span>' : '<span style="color:#22c55e;float:right">✓ valid</span>';
    const tamperSection = block.index > 0 ? `
        <div class="bc-tamper-section">
            <button class="bc-tamper-btn" data-index="${block.index}">Tamper this block</button>
            <div class="bc-tamper-form" style="display:none;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-top:0.5rem;">
                <input type="text" class="bc-tamper-input" value="${escHtml(block.data)}"
                    style="flex:1;min-width:160px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.2);border-radius:6px;color:#e5e7eb;padding:0.35rem 0.6rem;font-size:0.875rem;">
                <button class="bc-tamper-confirm-btn" data-index="${block.index}"
                    style="padding:0.35rem 0.9rem;background:#ef4444;border:none;border-radius:6px;color:#fff;font-size:0.875rem;cursor:pointer;">Apply</button>
                <button class="bc-tamper-cancel-btn"
                    style="padding:0.35rem 0.9rem;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:#9ca3af;font-size:0.875rem;cursor:pointer;">Cancel</button>
            </div>
        </div>` : '';
    return `
        <div class="bc-block" style="border-color:${border}">
            <div class="bc-block-header">
                <span class="bc-index">Block #${block.index}</span>
                <span class="bc-algo">${algoLabel}</span>
                ${badge}
            </div>
            <div class="bc-field"><span class="bc-label">Data</span><span class="bc-value">${escHtml(block.data)}</span></div>
            <div class="bc-field"><span class="bc-label">Nonce</span><span class="bc-value mono">${block.nonce}</span></div>
            <div class="bc-field"><span class="bc-label">Timestamp</span><span class="bc-value mono">${fmtTimestamp(block.timestamp)}</span></div>
            <div class="bc-field"><span class="bc-label">Prev hash</span><span class="bc-value mono hash-text">${block.previous_hash}</span></div>
            <div class="bc-field bc-hash-row"><span class="bc-label">Hash</span><span class="bc-value mono hash-text" style="color:${isInvalid ? '#ef4444' : '#4ade80'}">${block.hash}</span></div>
            ${tamperSection}
        </div>
        ${block.index < 99 ? '<div class="bc-arrow">↓</div>' : ''}
    `;
};

const escHtml = (s: string): string =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const renderSteps = (steps: readonly MineStep[], attempts: number): string => {
    const stepsHtml = steps.map(s => {
        const dataHtml = s.data.length > 0
            ? `<div class="step-data">${s.data.map(d => `<div class="step-data-item">${escHtml(d)}</div>`).join('')}</div>`
            : '';
        return `
            <div class="step-card">
                <div class="step-title"><span class="step-number">${s.step_number}</span>${escHtml(s.title)}</div>
                <div class="step-description">${escHtml(s.description)}</div>
                ${dataHtml}
            </div>`;
    }).join('');
    return `
        <div class="bc-steps-header">Mining steps — ${attempts.toLocaleString()} attempt(s)</div>
        ${stepsHtml}`;
};

const renderHistory = (): void => {
    const el = getElement('blockchain-history');
    if (!el) return;
    if (savedChains.length === 0) {
        el.innerHTML = '';
        return;
    }
    const cards = savedChains.map((chain, i) => {
        const genesis = chain.blocks[0];
        const algo = genesis?.hash_algo === 'keccak256' ? 'Keccak-256' : 'SHA-256';
        const diff = genesis?.difficulty ?? '?';
        const count = chain.blocks.length;
        const validation: ValidateResult = JSON.parse(blockchainValidate(JSON.stringify(chain)));
        const badge = validation.valid
            ? '<span style="color:#22c55e;font-weight:500">✓ valid</span>'
            : '<span style="color:#ef4444;font-weight:500">✗ tampered</span>';
        return `
            <div style="display:flex;align-items:center;gap:1rem;padding:0.5rem 0.75rem;background:#111827;border:1px solid #1f2937;border-radius:8px;margin-bottom:0.4rem;font-size:0.8rem;flex-wrap:wrap;">
                <span style="color:#9ca3af;white-space:nowrap;">Chain #${i + 1}</span>
                <span style="color:#6b7280;">${count} block${count !== 1 ? 's' : ''}</span>
                <span style="color:#6b7280;">D=${diff}</span>
                <span style="color:#6b7280;">${algo}</span>
                ${badge}
            </div>`;
    }).join('');
    el.innerHTML = `
        <div style="color:#6b7280;font-size:0.7rem;letter-spacing:0.07em;text-transform:uppercase;margin-bottom:0.5rem;">Previous chains</div>
        ${cards}
        <div style="border-top:1px solid #1f2937;margin:1rem 0 0.5rem;"></div>`;
};

const revalidateAndRender = (): void => {
    if (!chainState) return;
    const chainJson = JSON.stringify(chainState);
    const raw = blockchainValidate(chainJson);
    const validation: ValidateResult = JSON.parse(raw);
    const invalidIdx = validation.invalid_block_index ?? -1;

    const chainEl = getElement('blockchain-chain');
    if (chainEl) {
        chainEl.innerHTML = chainState.blocks.map(b =>
            renderBlockCard(b, !validation.valid && b.index >= invalidIdx && invalidIdx >= 0)
        ).join('');
    }
    setStatus(validation.message, validation.valid);
};

export const startChain = (): void => {
    if (!isWasmReady()) return;
    const algo = getHashAlgo();
    const difficulty = getDifficulty();

    setStatus('Mining genesis block…', null);
    const stepsEl = getElement('blockchain-steps');
    if (stepsEl) stepsEl.innerHTML = '';

    try {
        const raw = blockchainCreateGenesis(algo, difficulty);
        const result: ChainResult = JSON.parse(raw);
        if (!result.success || !result.chain) {
            setStatus(result.error ?? 'Failed to create genesis block', false);
            return;
        }
        // Extract mining steps from the genesis mine call by re-mining with steps endpoint
        // Genesis block returns a chain — show its block in the chain display
        if (chainState !== null) savedChains = [...savedChains, chainState];
        chainState = result.chain;
        revalidateAndRender();
        renderHistory();
        setMineSection(true);
        // Show genesis mine stats
        const genesisBlock = result.chain.blocks[0];
        if (stepsEl) {
            stepsEl.innerHTML = `<div class="bc-steps-header">Genesis block mined — nonce: ${genesisBlock.nonce}</div>`;
        }
    } catch (e) {
        setStatus(e instanceof Error ? e.message : 'Error', false);
    }
};

export const mineBlock = (): void => {
    if (!isWasmReady() || !chainState) return;
    const data = (getElement('blockchain-data') as HTMLTextAreaElement)?.value?.trim() ?? '';
    if (!data) {
        setStatus('Enter block data first', false);
        return;
    }
    const algo = getHashAlgo();
    const difficulty = getDifficulty();

    setStatus('Mining…', null);
    const stepsEl = getElement('blockchain-steps');
    if (stepsEl) stepsEl.innerHTML = '';

    // Yield to UI before the synchronous WASM mining loop
    setTimeout(() => {
        try {
            const raw = blockchainMineBlock(JSON.stringify(chainState!), data, algo, difficulty);
            const result: MineBlockResult = JSON.parse(raw);
            if (!result.success || !result.chain) {
                setStatus(result.error ?? 'Mining failed', false);
                return;
            }
            chainState = result.chain;
            revalidateAndRender();
            if (stepsEl) stepsEl.innerHTML = renderSteps(result.steps, result.attempts);
            // clear input
            const dataEl = getElement('blockchain-data') as HTMLTextAreaElement | null;
            if (dataEl) dataEl.value = '';
        } catch (e) {
            setStatus(e instanceof Error ? e.message : 'Error', false);
        }
    }, 0);
};

export const tamperBlock = (blockIndex: number, newData: string): void => {
    if (!isWasmReady() || !chainState) return;
    const raw = blockchainTamper(JSON.stringify(chainState), blockIndex, newData);
    const result: ChainResult = JSON.parse(raw);
    if (result.success && result.chain) {
        chainState = result.chain;
        revalidateAndRender();
        const stepsEl = getElement('blockchain-steps');
        if (!stepsEl) return;
        const validation: ValidateResult = JSON.parse(blockchainValidate(JSON.stringify(chainState)));
        if (validation.valid) {
            stepsEl.innerHTML = `
                <div class="step-card" style="border-left:3px solid #4ade80">
                    <div class="step-title"><span class="step-number">✓</span>Block #${blockIndex} restored</div>
                    <div class="step-description">The data matches the stored hash — the chain is valid again.</div>
                </div>`;
        } else {
            stepsEl.innerHTML = `
                <div class="step-card" style="border-left:3px solid #ef4444">
                    <div class="step-title"><span class="step-number">!</span>Block #${blockIndex} tampered</div>
                    <div class="step-description">Block data changed without re-mining. The hash no longer matches and the chain is now invalid. To fix it, you would need to re-mine every block from #${blockIndex} onward — this is why blockchains are tamper-evident.</div>
                </div>`;
        }
    }
};

export const resetChain = (): void => {
    if (chainState !== null) {
        savedChains = [...savedChains, chainState];
        renderHistory();
    }
    chainState = null;
    setMineSection(false);
    setStatus('Start a chain to begin', null);
    const chainEl = getElement('blockchain-chain');
    if (chainEl) chainEl.innerHTML = '';
    const stepsEl = getElement('blockchain-steps');
    if (stepsEl) stepsEl.innerHTML = '';
};

export const initBlockchain = (): void => {
    resetChain();
    const chainEl = getElement('blockchain-chain');
    if (chainEl) {
        chainEl.addEventListener('click', (e) => {
            const target = e.target as HTMLElement;

            const tamperBtn = target.closest('.bc-tamper-btn') as HTMLElement | null;
            if (tamperBtn) {
                const section = tamperBtn.closest('.bc-tamper-section') as HTMLElement | null;
                tamperBtn.style.display = 'none';
                const form = section?.querySelector('.bc-tamper-form') as HTMLElement | null;
                if (form) form.style.display = 'flex';
                return;
            }

            const cancelBtn = target.closest('.bc-tamper-cancel-btn') as HTMLElement | null;
            if (cancelBtn) {
                const section = cancelBtn.closest('.bc-tamper-section') as HTMLElement | null;
                const btn = section?.querySelector('.bc-tamper-btn') as HTMLElement | null;
                if (btn) btn.style.display = 'inline-block';
                const form = cancelBtn.closest('.bc-tamper-form') as HTMLElement | null;
                if (form) form.style.display = 'none';
                return;
            }

            const confirmBtn = target.closest('.bc-tamper-confirm-btn') as HTMLElement | null;
            if (confirmBtn) {
                const idx = parseInt(confirmBtn.dataset.index ?? '-1', 10);
                const input = confirmBtn.closest('.bc-tamper-form')?.querySelector('.bc-tamper-input') as HTMLInputElement | null;
                if (idx >= 0 && input) tamperBlock(idx, input.value);
            }
        });
    }
};

export const exportChain = (): void => {
    if (!chainState) return;
    const json = JSON.stringify(chainState, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chain-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
};
