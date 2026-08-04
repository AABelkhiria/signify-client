// Generates qualified-material vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { decodeBase64Url } from '../../reference/signify-ts/dist/keri/core/base64.js';
import { Matter } from '../../reference/signify-ts/dist/keri/core/matter.js';

const referenceSha = 'ae92eceb8e776ad57669707bff7f84db9390b711';

function deterministicRaw(length, salt) {
    return Uint8Array.from({ length }, (_, offset) =>
        (salt * 17 + offset * 29) % 256
    );
}

function hex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

function errorCase(name, operation) {
    try {
        operation();
    } catch (error) {
        return {
            name,
            reference_error_category: error?.constructor?.name ?? 'Unknown',
            reference_error_message: String(error?.message ?? error),
        };
    }
    throw new Error(`reference unexpectedly accepted rejected case ${name}`);
}

const fixedCases = Array.from(Matter.Sizes.entries())
    .filter(([, size]) => size.fs !== undefined)
    .map(([code], index) => {
        const raw = deterministicRaw(Matter._rawSize(code), index + 1);
        const material = new Matter({ raw, code });
        const parsed = new Matter({ qb64: material.qb64 });
        if (parsed.code !== code || hex(parsed.raw) !== hex(raw)) {
            throw new Error(`reference fixed round trip failed for ${code}`);
        }
        return {
            code,
            raw_hex: hex(raw),
            qb64: material.qb64,
            qb2_hex: hex(decodeBase64Url(material.qb64)),
            transferable: material.transferable,
            digestive: material.digestive,
        };
    });

const variableSpecifications = [
    ['4A', 6],
    ['5A', 5],
    ['6A', 4],
    ['4B', 6],
    ['5B', 5],
    ['6B', 4],
    ['7AAA', 6],
    ['8AAA', 5],
    ['9AAA', 4],
    ['7AAB', 6],
    ['8AAB', 5],
    ['9AAB', 4],
    ['4A', 12_288],
];

const variableCases = variableSpecifications.map(([code, rawLength], index) => {
    const raw = deterministicRaw(rawLength, index + 101);
    const material = new Matter({ raw, code });
    const parsed = new Matter({ qb64: material.qb64 });
    const reencodeError = errorCase(`reencode_variable_${material.code}`, () =>
        parsed.qb64
    );
    if (parsed.size !== undefined || hex(parsed.raw) !== hex(raw)) {
        throw new Error(`reference variable parse behavior changed for ${code}`);
    }
    return {
        input_code: code,
        output_code: material.code,
        raw_hex: hex(raw),
        size: material.size,
        both: material.both,
        qb64: material.qb64,
        qb2_hex: hex(decodeBase64Url(material.qb64)),
        reference_parse: {
            code: parsed.code,
            size_is_undefined: parsed.size === undefined,
            raw_hex: hex(parsed.raw),
            reencode_error_category: reencodeError.reference_error_category,
        },
    };
});

const emptyVariable = new Matter({ raw: new Uint8Array(), code: '4A' });
const parsedEmptyVariable = new Matter({ qb64: emptyVariable.qb64 });
variableCases.unshift({
    input_code: '4A',
    output_code: emptyVariable.code,
    raw_hex: '',
    size: emptyVariable.size,
    both: emptyVariable.both,
    qb64: emptyVariable.qb64,
    qb2_hex: hex(decodeBase64Url(emptyVariable.qb64)),
    reference_parse: {
        code: parsedEmptyVariable.code,
        size_is_undefined: parsedEmptyVariable.size === undefined,
        raw_hex: hex(parsedEmptyVariable.raw),
        reencode_error_category: errorCase('reencode_empty_variable', () =>
            parsedEmptyVariable.qb64
        ).reference_error_category,
    },
});

const streamRaw = deterministicRaw(40, 201);
const streamMaterial = new Matter({ raw: streamRaw, code: 'A' });
const streamQb64 = `${streamMaterial.qb64}tail`;
const streamParsed = new Matter({ qb64: streamQb64 });

const rejectedCases = [
    [errorCase('empty_qb64', () => new Matter({ qb64: '' })), 'EmptyInput'],
    [errorCase('unsupported_code', () => new Matter({ qb64: 'RAAA' })), 'UnsupportedCode'],
    [errorCase('truncated_fixed', () => new Matter({ qb64: 'A' })), 'Truncated'],
    [
        errorCase('short_fixed_raw', () =>
            new Matter({ raw: new Uint8Array(31), code: 'A' })
        ),
        'RawSizeMismatch',
    ],
    [
        errorCase('non_zero_code_padding', () =>
            new Matter({ qb64: `AQ${'A'.repeat(42)}` })
        ),
        'NonZeroPadding',
    ],
    [
        errorCase('non_zero_lead_byte', () =>
            new Matter({ qb64: '2AAABAAA' })
        ),
        'NonZeroPadding',
    ],
].map(([reference, rustErrorCategory]) => ({
    ...reference,
    rust_error_category: rustErrorCategory,
}));

const fixture = {
    schema_version: 1,
    upstream: 'https://github.com/WebOfTrust/signify-ts.git',
    reference_sha: referenceSha,
    generated_on: '2026-08-04',
    sources: [
        'src/keri/core/matter.ts',
        'test/core/matter.test.ts',
        'test/core/bexter.test.ts',
    ],
    binary_derivation:
        'qb2_hex is decodeBase64Url(reference Matter.qb64); pinned Matter._bexfil is unsupported',
    variable_parse_divergence:
        'pinned _exfil leaves size undefined and cannot re-encode; Rust decodes and validates the soft size',
    fixed_cases: fixedCases,
    variable_cases: variableCases,
    stream_cases: {
        raw_prefix: {
            input_raw_hex: hex(streamRaw),
            code: 'A',
            consumed_raw_bytes: streamMaterial.raw.length,
            qb64: streamMaterial.qb64,
        },
        qb64_prefix: {
            input: streamQb64,
            consumed_characters: streamMaterial.qb64.length,
            parsed_qb64: streamParsed.qb64,
        },
    },
    rejected_cases: rejectedCases,
};

const outputUrl = new URL('../../fixtures/cesr-matter/v1.json', import.meta.url);
mkdirSync(fileURLToPath(new URL('.', outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
