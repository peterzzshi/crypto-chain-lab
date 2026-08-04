import { initWasm, runRsaDemo, runSha256Demo, runWeierstrassDemo, runSecp256k1Demo } from './demos.ts';
import { getElement, getElements, onEnterKey, onEnterKeyUnlessShift } from './utils.ts';

const switchTab = (event: Event): void => {
    const target = event.target as HTMLElement;
    const tabName = target.dataset.tab;
    getElements('.tab-button').forEach(btn => btn.classList.remove('active'));
    target.classList.add('active');
    getElements('.panel').forEach(panel => panel.classList.add('hidden'));
    getElement(`${tabName}-panel`)?.classList.remove('hidden');
};

const registerClickHandler = (id: string, handler: () => void): void => {
    getElement(id)?.addEventListener('click', handler);
};

const registerEnterKeyHandler = (id: string, handler: () => void, allowShift = false): void => {
    const keyHandler = allowShift ? onEnterKeyUnlessShift(handler) : onEnterKey(handler);
    getElement(id)?.addEventListener('keypress', keyHandler as EventListener);
};

const setupEventListeners = (): void => {
    getElements('.tab-button').forEach(btn => btn.addEventListener('click', switchTab));

    registerClickHandler('rsa-run-btn', () => void runRsaDemo());
    registerClickHandler('sha256-run-btn', () => void runSha256Demo());
    registerClickHandler('weierstrass-run-btn', () => void runWeierstrassDemo());
    registerClickHandler('secp256k1-run-btn', () => void runSecp256k1Demo());

    ['rsa-message', 'rsa-p', 'rsa-q'].forEach(id =>
        registerEnterKeyHandler(id, () => void runRsaDemo())
    );
    registerEnterKeyHandler('sha256-message', () => void runSha256Demo(), true);
    ['weierstrass-key', 'weierstrass-a', 'weierstrass-b', 'weierstrass-p', 'weierstrass-gx', 'weierstrass-gy'].forEach(id =>
        registerEnterKeyHandler(id, () => void runWeierstrassDemo())
    );
    registerEnterKeyHandler('secp256k1-key', () => void runSecp256k1Demo());

    getElement('secp256k1-key')?.addEventListener('input', (e) => {
        const val = (e.target as HTMLInputElement).value.trim();
        const errorEl = getElement('secp256k1-key-error') as HTMLElement | null;
        if (!errorEl) return;
        if (!val) {
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        } else if (!/^(0x)?[0-9a-fA-F]{1,64}$/.test(val)) {
            errorEl.textContent = 'Must be a hex string up to 64 characters (0–9, a–f)';
            errorEl.style.display = 'inline';
        } else if (val.replace(/^0x/i, '').length < 1) {
            errorEl.textContent = 'Key must be at least 1 hex digit';
            errorEl.style.display = 'inline';
        } else {
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        }
    });
};

const init = async (): Promise<void> => {
    await initWasm();
    setupEventListeners();
};

void init();
