import { initWasm, runRsaDemo, runSha256Demo, runKeccak256Demo, runWeierstrassDemo, runSecp256k1Demo, runEcdsaSignDemo, runEcdsaVerifyDemo, runAes128Demo } from './demos.ts';
import { initBlockchain, startChain, mineBlock, resetChain, exportChain } from './blockchain.ts';
import { getElement, getElements, debounce } from './utils.ts';

const showPanel = (tabName: string): void => {
    getElements('.panel').forEach(p => p.classList.add('hidden'));
    getElement(`${tabName}-panel`)?.classList.remove('hidden');
};

const switchToPrimitive = (tabName: string): void => {
    showPanel(tabName);
    getElements('.tab-button').forEach(btn => btn.classList.remove('active'));
    const select = getElement('primitive-select') as HTMLSelectElement | null;
    if (select) select.value = tabName;
};

const switchToBlockchain = (): void => {
    showPanel('blockchain');
    getElements('.tab-button').forEach(btn => {
        const el = btn as HTMLElement;
        el.classList.toggle('active', el.dataset.tab === 'blockchain');
    });
    const select = getElement('primitive-select') as HTMLSelectElement | null;
    if (select) select.value = '';
};

const setupTabListeners = (): void => {
    // Primitive select
    const select = getElement('primitive-select') as HTMLSelectElement | null;
    if (select) {
        select.addEventListener('change', () => switchToPrimitive(select.value));
    }
    // Blockchain button (and any future top-level tab buttons)
    getElements('.tab-button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tab = (e.currentTarget as HTMLElement).dataset.tab;
            if (tab === 'blockchain') switchToBlockchain();
        });
    });
    // Difficulty slider label
    const diffSlider = getElement('blockchain-difficulty') as HTMLInputElement | null;
    const diffLabel = getElement('blockchain-difficulty-label');
    if (diffSlider && diffLabel) {
        diffSlider.addEventListener('input', () => { diffLabel.textContent = diffSlider.value; });
    }
};

const setupReactiveListeners = (): void => {
    const d300  = debounce(() => void runSha256Demo(), 300);
    const d300k = debounce(() => void runKeccak256Demo(), 300);
    const d400  = debounce(() => void runRsaDemo(), 400);
    const d400a = debounce(() => void runAes128Demo(), 400);
    const d400w = debounce(() => void runWeierstrassDemo(), 400);
    const d400s = debounce(() => void runSecp256k1Demo(), 400);

    getElement('sha256-message')?.addEventListener('input', d300);
    getElement('keccak256-message')?.addEventListener('input', d300k);

    ['rsa-message', 'rsa-p', 'rsa-q'].forEach(id =>
        getElement(id)?.addEventListener('input', d400)
    );
    ['aes128-plaintext', 'aes128-key'].forEach(id =>
        getElement(id)?.addEventListener('input', d400a)
    );
    ['weierstrass-key', 'weierstrass-a', 'weierstrass-b', 'weierstrass-p', 'weierstrass-gx', 'weierstrass-gy'].forEach(id =>
        getElement(id)?.addEventListener('input', d400w)
    );

    getElement('secp256k1-key')?.addEventListener('input', (e) => {
        const val = (e.target as HTMLInputElement).value.trim();
        const errorEl = getElement('secp256k1-key-error') as HTMLElement | null;
        if (errorEl) {
            if (!val || /^(0x)?[0-9a-fA-F]{1,64}$/.test(val)) {
                errorEl.textContent = '';
                errorEl.style.display = 'none';
            } else {
                errorEl.textContent = 'Must be a hex string up to 64 characters (0–9, a–f)';
                errorEl.style.display = 'inline';
            }
        }
        d400s();
    });
};

const setupExampleKeyChips = (): void => {
    getElements('.secp256k1-example-key').forEach(chip => {
        chip.addEventListener('click', () => {
            const keyInput = getElement('secp256k1-key') as HTMLInputElement | null;
            if (keyInput) {
                keyInput.value = (chip as HTMLElement).dataset.key ?? '';
                void runSecp256k1Demo();
            }
        });
    });
};

const copySignatureToVerify = (): void => {
    const resultsDiv = getElement('ecdsa-results');
    if (!resultsDiv) return;
    const keyValues = Array.from(resultsDiv.querySelectorAll('.key-value'));
    const extract = (label: string): string => {
        const el = keyValues.find(v => v.textContent?.trimStart().startsWith(`${label} =`));
        return el?.textContent?.split('=').slice(1).join('=').trim() ?? '';
    };
    const set = (id: string, val: string): void => {
        const el = getElement(id) as HTMLInputElement | null;
        if (el) el.value = val;
    };
    set('ecdsa-verify-pubkey-x', extract('x'));
    set('ecdsa-verify-pubkey-y', extract('y'));
    set('ecdsa-verify-r', extract('r'));
    set('ecdsa-verify-s', extract('s'));
    const msgInput = getElement('ecdsa-message') as HTMLInputElement | null;
    set('ecdsa-verify-message', msgInput?.value ?? '');
};

const init = async (): Promise<void> => {
    setupTabListeners();
    // Show RSA panel by default
    showPanel('rsa');
    await initWasm();
    setupReactiveListeners();
    setupExampleKeyChips();
    // Wire blockchain action buttons
    getElement('blockchain-start-btn')?.addEventListener('click', startChain);
    getElement('blockchain-mine-btn')?.addEventListener('click', mineBlock);
    getElement('blockchain-reset-btn')?.addEventListener('click', resetChain);
    getElement('blockchain-export-btn')?.addEventListener('click', exportChain);
    initBlockchain();
    getElement('ecdsa-sign-btn')?.addEventListener('click', async () => {
        await runEcdsaSignDemo();
        copySignatureToVerify();
    });
    getElement('ecdsa-verify-btn')?.addEventListener('click', () => void runEcdsaVerifyDemo());
    // Pre-run all algorithm demos
    void runRsaDemo();
    void runSha256Demo();
    void runKeccak256Demo();
    void runWeierstrassDemo();
    void runSecp256k1Demo();
    void runAes128Demo();
};

void init();
