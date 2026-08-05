import { initWasm, runRsaDemo, runSha256Demo, runKeccak256Demo, runWeierstrassDemo, runSecp256k1Demo } from './demos.ts';
import { getElement, getElements, debounce } from './utils.ts';

const switchTab = (event: Event): void => {
    const target = event.target as HTMLElement;
    const tabName = target.dataset.tab;
    getElements('.tab-button').forEach(btn => btn.classList.remove('active'));
    target.classList.add('active');
    getElements('.panel').forEach(panel => panel.classList.add('hidden'));
    getElement(`${tabName}-panel`)?.classList.remove('hidden');
};

const setupReactiveListeners = (): void => {
    const d300 = debounce(() => void runSha256Demo(), 300);
    const d300k = debounce(() => void runKeccak256Demo(), 300);
    const d400 = debounce(() => void runRsaDemo(), 400);
    const d400w = debounce(() => void runWeierstrassDemo(), 400);
    const d400s = debounce(() => void runSecp256k1Demo(), 400);

    getElement('sha256-message')?.addEventListener('input', d300);
    getElement('keccak256-message')?.addEventListener('input', d300k);

    ['rsa-message', 'rsa-p', 'rsa-q'].forEach(id =>
        getElement(id)?.addEventListener('input', d400)
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

const setupTabListeners = (): void => {
    getElements('.tab-button').forEach(btn => btn.addEventListener('click', switchTab));
};

const init = async (): Promise<void> => {
    setupTabListeners();
    await initWasm();
    setupReactiveListeners();
    setupExampleKeyChips();
    // Run all demos on load using default values
    void runRsaDemo();
    void runSha256Demo();
    void runKeccak256Demo();
    void runWeierstrassDemo();
    void runSecp256k1Demo();
};

void init();
