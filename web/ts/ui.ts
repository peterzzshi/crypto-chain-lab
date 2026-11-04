export type RsaKeyPair = {
    readonly n: string;
    readonly e: string;
    readonly d: string;
    readonly p: string;
    readonly q: string;
    readonly phi_n: string;
}

export type RsaStep = {
    readonly step_number: number;
    readonly title: string;
    readonly description: string;
    readonly formula: string;
    readonly result: string;
}

export type RsaBlock = {
    readonly index: number;
    readonly text_chunk: string;
    readonly message_number: string;
    readonly ciphertext: string;
    readonly decrypted_number: string;
}

export type RsaResult = {
    readonly key_pair?: RsaKeyPair;
    readonly steps: readonly RsaStep[];
    readonly success: boolean;
    readonly original_message: string;
    readonly decrypted_text?: string;
    readonly blocks?: readonly RsaBlock[];
}

export type Sha256Step = {
    readonly step_number: number;
    readonly title: string;
    readonly description: string;
    readonly data?: readonly string[];
}

export type Sha256Result = {
    readonly hash: string;
    readonly steps: readonly Sha256Step[];
}

export type Keccak256Step = {
    readonly step_number: number;
    readonly title: string;
    readonly description: string;
    readonly data?: readonly string[];
}

export type Keccak256Result = {
    readonly hash: string;
    readonly steps: readonly Keccak256Step[];
}

export type MerkleResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly root?: string;
    readonly tree?: readonly (readonly string[])[];
    readonly leaf_count: number;
}

export const buildMerkleHtml = (result: MerkleResult): string => {
    if (!result.success || !result.root || !result.tree) {
        return `<div style="color:#ef4444;font-size:0.875rem;">${result.error ?? 'Merkle error'}</div>`;
    }
    const short = (h: string): string => `${h.slice(0, 8)}…${h.slice(-4)}`;
    const levels = [...result.tree].reverse();
    const levelHtml = levels.map((level, li) => {
        const label = li === 0 ? 'Root' : li === levels.length - 1 ? 'Leaves (block hashes)' : `Level ${levels.length - 1 - li}`;
        const cells = level.map(h =>
            `<span style="display:inline-block;padding:0.2rem 0.45rem;background:#111827;border:1px solid #374151;border-radius:4px;font-family:monospace;font-size:0.7rem;color:${li === 0 ? '#4ade80' : '#9ca3af'};white-space:nowrap;" title="${h}">${short(h)}</span>`
        ).join('<span style="color:#4b5563;margin:0 0.2rem;">·</span>');
        return `<div style="margin-bottom:0.5rem;"><span style="font-size:0.7rem;color:#6b7280;display:block;margin-bottom:0.2rem;">${label}</span><div style="display:flex;flex-wrap:wrap;gap:0.25rem;align-items:center;">${cells}</div></div>`;
    }).join('<div style="text-align:center;color:#4b5563;font-size:0.8rem;margin:0.15rem 0;">↑</div>');
    return `
        <div style="padding:1rem;background:#0d1117;border:1px solid #1f2937;border-radius:8px;margin-top:0.75rem;">
            <div style="font-size:0.75rem;color:#6b7280;letter-spacing:0.07em;text-transform:uppercase;margin-bottom:0.75rem;">
                Merkle Tree — ${result.leaf_count} leaf${result.leaf_count !== 1 ? 'ves' : ''}
            </div>
            ${levelHtml}
            <div style="margin-top:0.75rem;border-top:1px solid #1f2937;padding-top:0.5rem;">
                <span style="font-size:0.7rem;color:#6b7280;">Root: </span>
                <span style="font-family:monospace;font-size:0.75rem;color:#4ade80;word-break:break-all;">${result.root}</span>
            </div>
        </div>`;
};

const renderStepCard = (stepNumber: number, title: string, description: string, content: string): string => `
    <div class="step-card">
        <div class="step-title">
            <span class="step-number">${stepNumber}</span>
            ${title}
        </div>
        <div class="step-description">${description}</div>
        ${content}
    </div>
`;

const renderKeyCard = (icon: string, title: string, values: string[]): string => `
    <div class="key-card">
        <h4>${icon} ${title}</h4>
        ${values.map(v => `<div class="key-value">${v}</div>`).join('')}
    </div>
`;

const renderKeyPairDisplay = ({ n, e, d, p, q, phi_n }: RsaKeyPair): string => `
    <div class="key-display">
        ${renderKeyCard('🔓', 'Public Key', [`n = ${n}`, `e = ${e}`])}
        ${renderKeyCard('🔐', 'Private Key', [`n = ${n}`, `d = ${d}`])}
        ${renderKeyCard('📊', 'Parameters', [`p = ${p}`, `q = ${q}`, `φ(n) = ${phi_n}`])}
    </div>
`;

const renderRsaStep = ({ step_number, title, description, formula, result }: RsaStep): string =>
    renderStepCard(step_number, title, description, `
        <div class="step-formula">${formula}</div>
        <div class="step-result">Result: ${result}</div>
    `);

const renderRsaBlocksTable = (blocks: readonly RsaBlock[]): string => {
    const rows = blocks.map(b =>
        `<tr>
            <td>${b.index}</td>
            <td style="font-family:monospace">${b.text_chunk}</td>
            <td style="font-family:monospace">${b.message_number}</td>
            <td style="font-family:monospace">${b.ciphertext}</td>
            <td style="color:${b.message_number === b.decrypted_number ? '#4ade80' : '#f87171'}">${b.message_number === b.decrypted_number ? '✓' : '✗'}</td>
        </tr>`
    ).join('');
    return `
        <div class="step-card" style="overflow-x:auto">
            <div class="step-title"><span class="step-number">●</span> Per-Block Encrypt / Decrypt</div>
            <table style="width:100%;border-collapse:collapse;font-size:0.8rem;margin-top:0.5rem">
                <thead>
                    <tr style="color:#9ca3af;text-align:left;border-bottom:1px solid #374151">
                        <th style="padding:4px 8px">#</th>
                        <th style="padding:4px 8px">chunk</th>
                        <th style="padding:4px 8px">m (ASCII)</th>
                        <th style="padding:4px 8px">c = mᵉ mod n</th>
                        <th style="padding:4px 8px">ok?</th>
                    </tr>
                </thead>
                <tbody style="color:#d1d5db">${rows}</tbody>
            </table>
        </div>`;
};

const renderSha256Step = ({ step_number, title, description, data = [] }: Sha256Step): string => {
    const dataHtml = data.length > 0
        ? `<div class="step-data">${data.map(item => `<div class="step-data-item">${item}</div>`).join('')}</div>`
        : '';
    return renderStepCard(step_number, title, description, dataHtml);
};

const renderMessage = (className: string, icon: string, message: string): string =>
    `<div class="${className}">${icon} ${message}</div>`;


export const buildRsaResultsHtml = ({ key_pair, steps, blocks }: RsaResult): string => {
    const keyPairHtml = key_pair ? renderKeyPairDisplay(key_pair) : '';
    const stepsHtml = steps.map(renderRsaStep).join('');
    const blocksHtml = blocks && blocks.length > 0 ? renderRsaBlocksTable(blocks) : '';
    return keyPairHtml + stepsHtml + blocksHtml;
};

export const buildSha256ResultsHtml = ({ hash, steps }: Sha256Result): string => {
    const hashHtml = `<div class="hash-result"><strong>SHA-256 Hash:</strong><br>${hash}</div>`;
    const stepsHtml = steps.map(renderSha256Step).join('');
    return hashHtml + stepsHtml;
};

export const buildKeccak256ResultsHtml = ({ hash, steps }: Keccak256Result): string => {
    const hashHtml = `<div class="hash-result"><strong>Keccak-256 Hash:</strong><br>${hash}</div>`;
    const stepsHtml = steps.map(step => {
        const { step_number, title, description, data = [] } = step;
        const dataHtml = data.length > 0
            ? `<div class="step-data">${data.map(item => `<div class="step-data-item">${item}</div>`).join('')}</div>`
            : '';
        return renderStepCard(step_number, title, description, dataHtml);
    }).join('');
    return hashHtml + stepsHtml;
};

export const buildErrorHtml = (message: string): string =>
    renderMessage('error-message', '❌', message);

export const buildLoadingHtml = (message: string): string =>
    renderMessage('loading', '⏳', message);


export const renderToContainer = (container: HTMLElement, html: string): void => {
    container.innerHTML = html;
};


export const renderRsaResults = (container: HTMLElement, result: RsaResult): void =>
    renderToContainer(container, buildRsaResultsHtml(result));

export const renderSha256Results = (container: HTMLElement, result: Sha256Result): void =>
    renderToContainer(container, buildSha256ResultsHtml(result));

export const renderKeccak256Results = (container: HTMLElement, result: Keccak256Result): void =>
    renderToContainer(container, buildKeccak256ResultsHtml(result));

export const renderError = (container: HTMLElement, message: string): void =>
    renderToContainer(container, buildErrorHtml(message));

export const renderLoading = (container: HTMLElement, message: string): void =>
    renderToContainer(container, buildLoadingHtml(message));

// ============================================================================
// ECC Types
// ============================================================================

export type EccStep = {
    readonly step_number: number;
    readonly title: string;
    readonly description: string;
    readonly formula: string;
    readonly result: string;
}

export type EccKeyPairResult = {
    readonly private_key: string;
    readonly public_key_x: string;
    readonly public_key_y: string;
    readonly public_key_compressed?: string;
    readonly public_key_uncompressed?: string;
    readonly curve: string;
}

export type EccResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly key_pair?: EccKeyPairResult;
    readonly steps: readonly EccStep[];
}

// ============================================================================
// ECC Curve Visualisation
// ============================================================================

// All finite affine points on y²=x³+x+6 (mod 11) — constant for this curve
const DEMO_CURVE_POINTS: ReadonlyArray<readonly [number, number]> = [
    [2, 4], [2, 7], [3, 5], [3, 6], [5, 2], [5, 9],
    [7, 2], [7, 9], [8, 3], [8, 8], [10, 2], [10, 9],
];

const parsePoint = (s: string): readonly [number, number] | null => {
    const m = s.match(/\((\d+),\s*(\d+)\)/);
    return m ? [parseInt(m[1], 10), parseInt(m[2], 10)] as const : null;
};

const renderDemoCurveSvg = (addendStr: string, resultStr: string): string => {
    const addend = parsePoint(addendStr);
    const result = parsePoint(resultStr);
    const size = 200;
    const margin = 18;
    const fieldSize = 11;
    const scale = (size - 2 * margin) / fieldSize;
    const toX = (x: number): string => (margin + x * scale).toFixed(1);
    const toY = (y: number): string => (size - margin - y * scale).toFixed(1);

    const grid = Array.from({ length: fieldSize + 1 }, (_, i) => {
        const v = (margin + i * scale).toFixed(1);
        return `<line x1="${v}" y1="${margin}" x2="${v}" y2="${size - margin}" stroke="#1f2937" stroke-width="0.5"/>` +
               `<line x1="${margin}" y1="${v}" x2="${size - margin}" y2="${v}" stroke="#1f2937" stroke-width="0.5"/>`;
    }).join('');

    const dots = DEMO_CURVE_POINTS.map(([x, y]) => {
        const isAddend = addend !== null && x === addend[0] && y === addend[1];
        const isResult = result !== null && x === result[0] && y === result[1];
        const isG = x === 2 && y === 7;
        const fill = isResult ? '#4ade80' : isAddend ? '#fb923c' : isG ? '#60a5fa' : '#4b5563';
        const r = (isResult || isAddend) ? 6 : isG ? 5 : 3.5;
        return `<circle cx="${toX(x)}" cy="${toY(y)}" r="${r}" fill="${fill}" opacity="0.9"/>`;
    }).join('');

    const gLabelX = (margin + 2 * scale + 6).toFixed(1);
    const gLabelY = (size - margin - 7 * scale - 5).toFixed(1);
    const gLabel = `<text x="${gLabelX}" y="${gLabelY}" fill="#93c5fd" font-size="9" font-family="monospace">G</text>`;

    const legend = `<circle cx="14" cy="14" r="4" fill="#4ade80"/><text x="22" y="18" fill="#9ca3af" font-size="9">result</text>` +
        `<circle cx="14" cy="28" r="4" fill="#fb923c"/><text x="22" y="32" fill="#9ca3af" font-size="9">addend</text>` +
        `<circle cx="14" cy="42" r="3.5" fill="#60a5fa"/><text x="22" y="46" fill="#9ca3af" font-size="9">G=(2,7)</text>`;

    return `<svg width="${size}" height="${size}" style="background:#111827;border-radius:6px;margin:0.75rem 0;display:block">${grid}${dots}${gLabel}${legend}</svg>`;
};

const renderSecp256k1CurveSvg = (): string => {
    const size = 200;
    const margin = 20;
    const xMin = -2, xMax = 3, yMin = -4, yMax = 4;
    const span = size - 2 * margin;
    const toX = (x: number): string => (margin + ((x - xMin) / (xMax - xMin)) * span).toFixed(1);
    const toY = (y: number): string => (size - margin - ((y - yMin) / (yMax - yMin)) * span).toFixed(1);

    const steps = Math.round((xMax - xMin) / 0.04) + 1;
    const xValues = Array.from({ length: steps }, (_, i) => xMin + i * 0.04);
    const { posPoints, negPoints } = xValues.reduce<{ posPoints: string[]; negPoints: string[] }>(
        (acc, xi) => {
            const y2 = xi ** 3 + 7;
            if (y2 < 0) return acc;
            const y = Math.sqrt(y2);
            return {
                posPoints: [...acc.posPoints, `${toX(xi)},${toY(y)}`],
                negPoints: [...acc.negPoints, `${toX(xi)},${toY(-y)}`],
            };
        },
        { posPoints: [], negPoints: [] },
    );

    const axes = `<line x1="${toX(xMin)}" y1="${toY(0)}" x2="${toX(xMax)}" y2="${toY(0)}" stroke="#374151" stroke-width="1"/>` +
        `<line x1="${toX(0)}" y1="${toY(yMin)}" x2="${toX(0)}" y2="${toY(yMax)}" stroke="#374151" stroke-width="1"/>`;

    const curves = (posPoints.length > 1 ? `<polyline points="${posPoints.join(' ')}" fill="none" stroke="#60a5fa" stroke-width="2" stroke-linecap="round"/>` : '') +
        (negPoints.length > 1 ? `<polyline points="${negPoints.join(' ')}" fill="none" stroke="#60a5fa" stroke-width="2" stroke-linecap="round"/>` : '');

    const label = `<text x="${(size / 2 - 38).toFixed(0)}" y="${margin - 5}" fill="#9ca3af" font-size="10" font-family="monospace">y² = x³ + 7</text>`;

    return `<svg width="${size}" height="${size}" style="background:#111827;border-radius:6px;margin:0.75rem 0;display:block">${axes}${curves}${label}</svg>`;
};

// ============================================================================
// ECC Rendering
// ============================================================================

const truncate = (s: string, n = 16): string => s.length > n * 2 ? `${s.slice(0, n)}…` : s;

const renderEccKeyPairDisplay = (kp: EccKeyPairResult): string => {
    const base = [
        `k = ${truncate(kp.private_key)}`,
        `Qx = ${kp.public_key_x.length > 16 ? '0x' + truncate(kp.public_key_x) : kp.public_key_x}`,
        `Qy = ${kp.public_key_y.length > 16 ? '0x' + truncate(kp.public_key_y) : kp.public_key_y}`,
    ];
    const compressed = kp.public_key_compressed
        ? renderKeyCard('📦', 'Compressed (33B)', [truncate(kp.public_key_compressed, 33)])
        : '';
    const uncompressed = kp.public_key_uncompressed
        ? renderKeyCard('📭', 'Uncompressed (65B)', [truncate(kp.public_key_uncompressed, 33)])
        : '';
    return `<div class="key-display">${renderKeyCard('🔑', `Public Key (${kp.curve})`, base)}${compressed}${uncompressed}</div>`;
};

// Weierstrass demo: formula = "T = (x,y)", result = "R = (x,y)" for double-and-add steps.
// SVG only shown when showSvg is true (i.e. curve matches the hardcoded DEMO_CURVE_POINTS for p=11).
const renderWeierstrassStep = (step: EccStep, showSvg: boolean): string => {
    const addendStr = step.formula.startsWith('T = ') ? step.formula.slice(4) : null;
    const resultStr = step.result.startsWith('R = ') ? step.result.slice(4) : null;
    const svg = showSvg && addendStr !== null && resultStr !== null
        ? renderDemoCurveSvg(addendStr, resultStr)
        : '';
    return renderStepCard(
        step.step_number, step.title, step.description,
        `<div class="step-formula">${step.formula}</div><div class="step-result">${step.result}</div>${svg}`,
    );
};

// secp256k1: show the real curve SVG on the "Short Weierstrass Curve" parameter step
const renderSecp256k1Step = (step: EccStep): string => {
    const svg = step.title.startsWith('Short Weierstrass Curve')
        ? renderSecp256k1CurveSvg()
        : '';
    return renderStepCard(
        step.step_number, step.title, step.description,
        `<div class="step-formula">${step.formula}</div><div class="step-result">${step.result}</div>${svg}`,
    );
};

export const buildWeierstrassResultsHtml = (result: EccResult): string => {
    const keyPairHtml = result.key_pair ? renderEccKeyPairDisplay(result.key_pair) : '';
    // Only render the SVG overlay for the hardcoded demo curve y²=x³+x+6 (mod 11)
    const curve = result.key_pair?.curve ?? '';
    const isDefaultCurve = curve.includes('+1x+6') && curve.endsWith('(mod 11)');
    const stepsHtml = result.steps.map(step => renderWeierstrassStep(step, isDefaultCurve)).join('');
    return keyPairHtml + stepsHtml;
};

export const buildSecp256k1ResultsHtml = (result: EccResult): string => {
    const keyPairHtml = result.key_pair ? renderEccKeyPairDisplay(result.key_pair) : '';
    const stepsHtml = result.steps.map(renderSecp256k1Step).join('');
    return keyPairHtml + stepsHtml;
};

export const renderWeierstrassResults = (container: HTMLElement, result: EccResult): void =>
    renderToContainer(container, buildWeierstrassResultsHtml(result));

export const renderSecp256k1Results = (container: HTMLElement, result: EccResult): void =>
    renderToContainer(container, buildSecp256k1ResultsHtml(result));

export type EcdsaSignResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly r?: string;
    readonly s?: string;
    readonly public_key_x?: string;
    readonly public_key_y?: string;
    readonly message_hash?: string;
}

export const buildEcdsaSignResultsHtml = (result: EcdsaSignResult): string => {
    if (!result.success || !result.r || !result.s) {
        return buildErrorHtml(result.error ?? 'Signing failed');
    }
    return `
        <div class="key-display">
            ${renderKeyCard('✍️', 'Signature', [
                `r = ${result.r}`,
                `s = ${result.s}`,
            ])}
            ${renderKeyCard('🔑', 'Public Key', [
                `x = ${result.public_key_x ?? ''}`,
                `y = ${result.public_key_y ?? ''}`,
            ])}
            ${renderKeyCard('🔏', 'Message Hash (SHA-256)', [
                result.message_hash ?? '',
            ])}
        </div>
    `;
};

export const renderEcdsaSignResults = (container: HTMLElement, result: EcdsaSignResult): void =>
    renderToContainer(container, buildEcdsaSignResultsHtml(result));

export type EcdsaVerifyResult = {
    readonly valid: boolean;
    readonly error?: string;
    readonly message: string;
}

export const buildEcdsaVerifyResultsHtml = (result: EcdsaVerifyResult): string => {
    if (result.error) return buildErrorHtml(result.error);
    const color = result.valid ? '#4ade80' : '#f87171';
    const icon = result.valid ? '✅' : '❌';
    const label = result.valid ? 'Signature is VALID' : 'Signature is INVALID';
    return `
        <div class="step-card" style="border-left:3px solid ${color}">
            <div class="step-title" style="color:${color}">${icon} ${label}</div>
            <div class="step-description">${result.message}</div>
        </div>
    `;
};

export const renderEcdsaVerifyResults = (container: HTMLElement, result: EcdsaVerifyResult): void =>
    renderToContainer(container, buildEcdsaVerifyResultsHtml(result));

export type Aes128Step = {
    readonly step_number: number;
    readonly title: string;
    readonly description: string;
    readonly state_hex: readonly string[];
};

export type Aes128DemoResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly plaintext_hex: string;
    readonly key_hex: string;
    readonly ciphertext_hex: string;
    readonly decrypted_hex: string;
    readonly steps: readonly Aes128Step[];
};

export const buildAes128ResultsHtml = (result: Aes128DemoResult): string => {
    if (!result.success) return buildErrorHtml(result.error ?? 'AES-128 failed');
    const summary = `
        <div class="key-display">
            ${renderKeyCard('🔐', 'AES-128 Result', [
                `Plaintext:  ${result.plaintext_hex}`,
                `Key:        ${result.key_hex}`,
                `Ciphertext: ${result.ciphertext_hex}`,
                `Decrypted:  ${result.decrypted_hex}`,
            ])}
        </div>`;
    const stepsHtml = result.steps.map(step => `
        <div class="step-card">
            <div class="step-number">Step ${step.step_number}</div>
            <div class="step-title">${step.title}</div>
            <div class="step-description">${step.description}</div>
            <div class="step-values">
                ${step.state_hex.map(line => `<div class="step-value"><code>${line}</code></div>`).join('')}
            </div>
        </div>`).join('');
    return summary + '<div class="steps-container">' + stepsHtml + '</div>';
};

export const renderAes128Results = (container: HTMLElement, result: Aes128DemoResult): void =>
    renderToContainer(container, buildAes128ResultsHtml(result));

export type SchnorrSignResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly r?: string;
    readonly s?: string;
    readonly public_key_x?: string;
    readonly message_hash?: string;
}

export const buildSchnorrSignResultsHtml = (result: SchnorrSignResult): string => {
    if (!result.success || !result.r || !result.s) {
        return buildErrorHtml(result.error ?? 'Schnorr signing failed');
    }
    return `
        <div class="key-display">
            ${renderKeyCard('✍️', 'Schnorr Signature (BIP-340)', [
                `r = ${result.r}`,
                `s = ${result.s}`,
            ])}
            ${renderKeyCard('🔑', 'Public Key (x-only)', [
                `x = ${result.public_key_x ?? ''}`,
            ])}
            ${renderKeyCard('🔏', 'Message Hash (SHA-256)', [
                result.message_hash ?? '',
            ])}
        </div>
    `;
};

export const renderSchnorrSignResults = (container: HTMLElement, result: SchnorrSignResult): void =>
    renderToContainer(container, buildSchnorrSignResultsHtml(result));

export type SchnorrVerifyResult = {
    readonly valid: boolean;
    readonly error?: string;
    readonly message: string;
}

export const buildSchnorrVerifyResultsHtml = (result: SchnorrVerifyResult): string => {
    if (result.error) return buildErrorHtml(result.error);
    const color = result.valid ? '#4ade80' : '#f87171';
    const icon = result.valid ? '✅' : '❌';
    const label = result.valid ? 'Signature is VALID' : 'Signature is INVALID';
    return `
        <div class="step-card" style="border-left:3px solid ${color}">
            <div class="step-title" style="color:${color}">${icon} ${label}</div>
            <div class="step-description">${result.message}</div>
        </div>
    `;
};

export const renderSchnorrVerifyResults = (container: HTMLElement, result: SchnorrVerifyResult): void =>
    renderToContainer(container, buildSchnorrVerifyResultsHtml(result));

export type BlsSignResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly pubkey?: string;
    readonly signature?: string;
    readonly message_hash?: string;
}

export type BlsVerifyResult = {
    readonly valid: boolean;
    readonly error?: string;
    readonly message: string;
}

export type BlsSignerInfo = {
    readonly index: number;
    readonly pubkey: string;
    readonly signature: string;
}

export type BlsAggregateDemoResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly signers?: BlsSignerInfo[];
    readonly aggregate_sig?: string;
    readonly aggregate_valid?: boolean;
    readonly message_hash?: string;
}

export const buildBlsSignResultsHtml = (result: BlsSignResult): string => {
    if (!result.success || !result.pubkey || !result.signature) {
        return buildErrorHtml(result.error ?? 'BLS signing failed');
    }
    return `
        <div class="key-display">
            ${renderKeyCard('🔑', 'BLS12-381 Public Key (G1, compressed)', [
                `pk = ${result.pubkey}`,
            ])}
            ${renderKeyCard('✍️', 'BLS Signature (G2, compressed)', [
                `sig = ${result.signature}`,
            ])}
            ${renderKeyCard('🔏', 'Message Hash (SHA-256)', [
                result.message_hash ?? '',
            ])}
        </div>
    `;
};

export const renderBlsSignResults = (container: HTMLElement, result: BlsSignResult): void =>
    renderToContainer(container, buildBlsSignResultsHtml(result));

export const buildBlsVerifyResultsHtml = (result: BlsVerifyResult): string => {
    if (result.error) return buildErrorHtml(result.error);
    const color = result.valid ? '#4ade80' : '#f87171';
    const icon = result.valid ? '✅' : '❌';
    const label = result.valid ? 'Signature is VALID' : 'Signature is INVALID';
    return `
        <div class="step-card" style="border-left:3px solid ${color}">
            <div class="step-title" style="color:${color}">${icon} ${label}</div>
            <div class="step-description">${result.message}</div>
        </div>
    `;
};

export const renderBlsVerifyResults = (container: HTMLElement, result: BlsVerifyResult): void =>
    renderToContainer(container, buildBlsVerifyResultsHtml(result));

export const buildBlsAggregateResultsHtml = (result: BlsAggregateDemoResult): string => {
    if (!result.success) {
        return buildErrorHtml(result.error ?? 'BLS aggregation failed');
    }
    const signersHtml = (result.signers ?? [])
        .map(s => renderKeyCard(`#${s.index}`, `Signer ${s.index} — BLS Key & Sig`, [
            `pk = ${s.pubkey}`,
            `sig = ${s.signature}`,
        ]))
        .join('');
    const valid = result.aggregate_valid === true;
    const color = valid ? '#4ade80' : '#f87171';
    const icon = valid ? '✅' : '❌';
    const label = valid ? 'Aggregate signature is VALID' : 'Aggregate signature is INVALID';
    return `
        <div class="key-display">
            ${signersHtml}
            ${renderKeyCard('🔗', 'Aggregate Signature (G2)', [
                `agg_sig = ${result.aggregate_sig ?? ''}`,
            ])}
            <div class="step-card" style="border-left:3px solid ${color}">
                <div class="step-title" style="color:${color}">${icon} ${label}</div>
                <div class="step-description">Verified with one pairing call: e(∑pkᵢ, H(m)) = e(G1, agg_sig).</div>
            </div>
        </div>
    `;
};

export const renderBlsAggregateResults = (container: HTMLElement, result: BlsAggregateDemoResult): void =>
    renderToContainer(container, buildBlsAggregateResultsHtml(result));

export type MpcShareInfo = {
    readonly index: number;
    readonly value: string;
}

export type MpcSplitDemoResult = {
    readonly success: boolean;
    readonly error?: string;
    readonly shares?: readonly MpcShareInfo[];
    readonly reconstructed_key_hex?: string;
    readonly reconstruction_valid?: boolean;
    readonly public_key_x?: string;
    readonly public_key_y?: string;
    readonly message_hash?: string;
    readonly ecdsa_r?: string;
    readonly ecdsa_s?: string;
    readonly signature_valid?: boolean;
}

export const buildMpcShamirResultsHtml = (result: MpcSplitDemoResult): string => {
    if (!result.success) return buildErrorHtml(result.error ?? 'MPC Shamir demo failed');
    const sharesHtml = (result.shares ?? []).map(s =>
        renderKeyCard(`Share ${s.index}`, `Shamir Share #${s.index}`, [`f(${s.index}) = ${s.value}`])
    ).join('');
    const recon = result.reconstruction_valid === true;
    const reconColor = recon ? '#4ade80' : '#f87171';
    const sigValid = result.signature_valid === true;
    const sigColor = sigValid ? '#4ade80' : '#f87171';
    return `
        <div class="key-display">
            ${sharesHtml}
            ${renderKeyCard('🔑', 'Reconstructed Key (from shares 1 & 3)', [
                `d = ${result.reconstructed_key_hex ?? ''}`,
            ])}
            <div class="step-card" style="border-left:3px solid ${reconColor}">
                <div class="step-title" style="color:${reconColor}">${recon ? '✅' : '❌'} Reconstruction ${recon ? 'VALID' : 'INVALID'}</div>
                <div class="step-description">Lagrange interpolation over 𝔽_n using any 2 of 3 shares recovers the original private key.</div>
            </div>
            ${renderKeyCard('📍', 'Public Key (secp256k1)', [
                `Qx = ${result.public_key_x ?? ''}`,
                `Qy = ${result.public_key_y ?? ''}`,
            ])}
            ${renderKeyCard('✍️', 'ECDSA Signature (RFC 6979)', [
                `r = ${result.ecdsa_r ?? ''}`,
                `s = ${result.ecdsa_s ?? ''}`,
            ])}
            <div class="step-card" style="border-left:3px solid ${sigColor}">
                <div class="step-title" style="color:${sigColor}">${sigValid ? '✅' : '❌'} Signature ${sigValid ? 'VALID' : 'INVALID'}</div>
                <div class="step-description">Message signed with reconstructed key and verified against derived public key.</div>
            </div>
        </div>
    `;
};

export const renderMpcShamirResults = (container: HTMLElement, result: MpcSplitDemoResult): void =>
    renderToContainer(container, buildMpcShamirResultsHtml(result));
