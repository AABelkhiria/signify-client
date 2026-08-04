// Generates CESR derivation-code vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
    BexDex,
    DigiDex,
    Matter,
    MtrDex,
    NonTransDex,
    NumDex,
    Sizage,
} from '../../reference/signify-ts/dist/keri/core/matter.js';

const referenceSha = 'ae92eceb8e776ad57669707bff7f84db9390b711';

const familyCodices = [
    ['general_matter', MtrDex],
    ['non_transferable', NonTransDex],
    ['digest', DigiDex],
    ['numeric', NumDex],
    ['base64_text', BexDex],
];

const codes = Array.from(Matter.Sizes.entries(), ([code, size]) => ({
    code,
    hard_size: size.hs,
    soft_size: size.ss,
    full_size: size.fs ?? null,
    lead_size: size.ls,
    raw_size: size.fs === undefined ? null : Matter._rawSize(code),
    families: familyCodices
        .filter(([, codex]) => codex.has(code))
        .map(([name]) => name),
}));

const hardSelectors = Array.from(Matter.Hards.entries(), ([selector, hardSize]) => ({
    selector,
    hard_size: hardSize,
}));

const sizage = new Sizage(1, 2, 3, 4);
if (sizage.hs !== 1 || sizage.ss !== 2 || sizage.fs !== 3 || sizage.ls !== 4) {
    throw new Error('reference Sizage property order changed');
}

let rejectedErrorCategory;
try {
    new Matter({ qb64: 'RAAA' });
} catch (error) {
    rejectedErrorCategory = error?.constructor?.name;
}
if (rejectedErrorCategory !== 'Error') {
    throw new Error('reference unexpectedly accepted unsupported hard code R');
}

const fixture = {
    schema_version: 1,
    upstream: 'https://github.com/WebOfTrust/signify-ts.git',
    reference_sha: referenceSha,
    generated_on: '2026-08-04',
    sources: [
        'src/keri/core/matter.ts',
        'test/core/matter.test.ts',
    ],
    sizage_constructor_case: {
        input: [1, 2, 3, 4],
        hard_size: sizage.hs,
        soft_size: sizage.ss,
        full_size: sizage.fs,
        lead_size: sizage.ls,
    },
    codes,
    hard_selectors: hardSelectors,
    rejected_cases: [
        {
            operation: 'Matter({ qb64 })',
            input: 'RAAA',
            hard_code: 'R',
            reference_error_category: rejectedErrorCategory,
            rust_error_category: 'UnsupportedCode',
        },
    ],
};

const outputUrl = new URL('../../fixtures/cesr-code-tables/v1.json', import.meta.url);
mkdirSync(fileURLToPath(new URL('.', outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
