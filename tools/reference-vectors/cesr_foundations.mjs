// Generates CESR foundation vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
    decodeBase64Url,
    encodeBase64Url,
} from '../../reference/signify-ts/dist/keri/core/base64.js';
import {
    b64ToInt,
    intToB64,
} from '../../reference/signify-ts/dist/keri/core/core.js';
import {
    bytesToInt,
    intToBytes,
} from '../../reference/signify-ts/dist/keri/core/utils.js';

const referenceSha = 'ae92eceb8e776ad57669707bff7f84db9390b711';

function padded(value) {
    return value + '='.repeat((4 - (value.length % 4)) % 4);
}

const rawCases = [
    [],
    [102],
    [102, 105],
    [102, 105, 115],
    [102, 105, 115, 104],
    [248],
    [252],
    [
        240, 159, 143, 179, 239, 184, 143, 240, 159, 143, 179, 239, 184,
        143,
    ],
];

const base64Cases = rawCases.map((raw) => {
    const encoded = encodeBase64Url(Uint8Array.from(raw));
    const acceptedDecodings = [...new Set([encoded, padded(encoded)])];
    for (const candidate of acceptedDecodings) {
        const decoded = Array.from(decodeBase64Url(candidate));
        if (JSON.stringify(decoded) !== JSON.stringify(raw)) {
            throw new Error(`reference Base64 round trip failed for ${candidate}`);
        }
    }
    return { raw, encoded, accepted_decodings: acceptedDecodings };
});

const integerCases = [
    [0, 0],
    [0, 1],
    [27, 1],
    [27, 2],
    [80, 1],
    [4095, 1],
    [4096, 1],
    [6011, 1],
].map(([value, minimumWidth]) => {
    const encoded = intToB64(value, minimumWidth);
    const decoded = encoded.length === 0 ? null : b64ToInt(encoded);
    return {
        value: String(value),
        minimum_width: minimumWidth,
        encoded,
        decoded: decoded === null ? null : String(decoded),
    };
});

const byteIntegerCases = [
    [0, 2],
    [1, 2],
    [0, 8],
    [1, 8],
    [0, 16],
    [1, 16],
    [66051, 8],
].map(([value, length]) => {
    const encoded = Array.from(intToBytes(value, length));
    return {
        value: String(value),
        length,
        encoded,
        decoded: String(bytesToInt(Uint8Array.from(encoded))),
    };
});

let emptyIntegerRejected = false;
try {
    b64ToInt('');
} catch {
    emptyIntegerRejected = true;
}
if (!emptyIntegerRejected) {
    throw new Error('reference unexpectedly accepted an empty Base64 integer');
}

const fixture = {
    schema_version: 1,
    upstream: 'https://github.com/WebOfTrust/signify-ts.git',
    reference_sha: referenceSha,
    generated_on: '2026-08-03',
    base64_cases: base64Cases,
    integer_cases: integerCases,
    byte_integer_cases: byteIntegerCases,
    rejected_cases: [
        {
            operation: 'decode_u64',
            input: '',
            reference_error_category: 'Error',
            rust_error_category: 'EmptyInput',
        },
    ],
    strict_rejections: [
        {
            operation: 'decode_url_safe',
            input: 'A',
            reference_output: [],
            rust_error_category: 'InvalidLength',
        },
        {
            operation: 'decode_url_safe',
            input: '+A',
            reference_output: Array.from(decodeBase64Url('+A')),
            rust_error_category: 'InvalidBase64Character',
        },
        {
            operation: 'decode_url_safe',
            input: 'Zh',
            reference_output: Array.from(decodeBase64Url('Zh')),
            rust_error_category: 'NonCanonicalBase64',
        },
        {
            operation: 'decode_url_safe',
            input: 'Zg=',
            reference_output: Array.from(decodeBase64Url('Zg=')),
            rust_error_category: 'InvalidBase64Padding',
        },
    ],
};

const outputUrl = new URL('../../fixtures/cesr-foundations/v1.json', import.meta.url);
mkdirSync(fileURLToPath(new URL('.', outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
