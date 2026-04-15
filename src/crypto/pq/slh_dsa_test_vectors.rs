//! Vecteurs de test FIPS 205 pour SLH-DSA (SPHINCS+)
//!
//! References:
//! - FIPS PUB 205 (2024): https://doi.org/10.6028/NIST.FIPS.205
//! - NIST CAVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
//!
//! Ces vecteurs sont generes selon les specifications FIPS 205 pour les parameters
//! SHA2-128s (n=16, h=63, d=7, a=12, k=14, w=16)

/// Seed de test pour generation deterministic (32 octets)
/// Utilise pour reproduire les sames keys dans les tests
pub const TEST_SEED_1: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Seed de test alternatif
pub const TEST_SEED_2: &[u8] = &[
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
];

/// Seed de test avec zeros (cas limite)
pub const TEST_SEED_ZEROS: &[u8] = &[0x00; 32];

/// Seed de test avec uns (cas limite)
pub const TEST_SEED_ONES: &[u8] = &[0xff; 32];

/// Messages de test de differentes tailles
pub const MESSAGE_EMPTY: &[u8] = b"";
pub const MESSAGE_SHORT: &[u8] = b"Hello, World!";
pub const MESSAGE_MEDIUM: &[u8] = b"The quick brown fox jumps over the lazy dog. This is a standard test message for cryptographic operations.";
pub const MESSAGE_LONG: &[u8] = &[0x42u8; 10000]; // 10KB of data

/// Message avec caracteres speciaux et UTF-8
pub const MESSAGE_UTF8: &[u8] = "Test avec caracteres speciaux: eaucñ 日本語 🎉".as_bytes();

/// Message avec octets nuls et valeurs extreme
pub const MESSAGE_BINARY: &[u8] = &[
    0x00, 0x01, 0x7f, 0x80, 0xff, 0x00, 0x00, 0x00,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
];

/// Key publique attendue pour TEST_SEED_1 (parameters SHA2-128s)
/// Taille: 32 octets pour SHA2-128s
pub const EXPECTED_PK_128S: &[u8] = &[
    // Ces valeurs seraient generees par un outil de reference FIPS 205
    // Pour les tests, on uses des placeholders qui seront remplaces
    // par les vraies valeurs lors de l'execution
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Key secret attendue pour TEST_SEED_1 (parameters SHA2-128s)
/// Taille: 64 octets pour SHA2-128s
pub const EXPECTED_SK_128S: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Signature attendue pour MESSAGE_SHORT avec TEST_SEED_1
/// Taille: 7856 octets pour SHA2-128s
/// Note: En pratique, on ne stocke pas la signature complete ici
/// mais on checks les propertys (taille, format)
pub const EXPECTED_SIG_SIZE_128S: usize = 7856;
pub const EXPECTED_PK_SIZE_128S: usize = 32;
pub const EXPECTED_SK_SIZE_128S: usize = 64;

/// Tailles pour les autres parameters
pub const SIG_SIZE_128F: usize = 17088;
pub const SIG_SIZE_192S: usize = 16224;
pub const SIG_SIZE_192F: usize = 49248;
pub const SIG_SIZE_256S: usize = 29792;
pub const SIG_SIZE_256F: usize = 92672;

pub const PK_SIZE_128: usize = 32;
pub const PK_SIZE_192: usize = 48;
pub const PK_SIZE_256: usize = 64;

pub const SK_SIZE_128: usize = 64;
pub const SK_SIZE_192: usize = 96;
pub const SK_SIZE_256: usize = 128;

/// Data pour tests de malleabilite
/// Une signature modifiee qui ne devrait pas be valide
pub const MALLEABLE_SIG_HEADER: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, // Version incorrecte
];

/// Data pour tests de corruption
/// Indices d'octets critiques dans la signature qui ne doivent pas be modifies
pub const CRITICAL_SIG_OFFSETS: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 7];

/// Nombre de signatures a generate pour tests de non-collision
pub const NON_COLLISION_ITERATIONS: usize = 100;

/// Messages pour tests de domaine separe
pub const DOMAIN_SEPARATION_MESSAGES: &[&[u8]] = &[
    b"domain1:message",
    b"domain2:message",
    b"domain1:message", // Identique au premier
];

/// Structure pour les cas de test nommes
pub struct TestCase {
    pub name: &'static str,
    pub seed: &'static [u8],
    pub message: &'static [u8],
    pub description: &'static str,
}

/// Cas de test standards
pub const STANDARD_TEST_CASES: &[TestCase] = &[
    TestCase {
        name: "empty_message",
        seed: TEST_SEED_1,
        message: MESSAGE_EMPTY,
        description: "Message vide (0 octet)",
    },
    TestCase {
        name: "short_message",
        seed: TEST_SEED_1,
        message: MESSAGE_SHORT,
        description: "Message court standard",
    },
    TestCase {
        name: "medium_message",
        seed: TEST_SEED_1,
        message: MESSAGE_MEDIUM,
        description: "Message moyen avec espaces",
    },
    TestCase {
        name: "long_message",
        seed: TEST_SEED_1,
        message: MESSAGE_LONG,
        description: "Message long (10KB)",
    },
    TestCase {
        name: "utf8_message",
        seed: TEST_SEED_1,
        message: MESSAGE_UTF8,
        description: "Message avec caracteres UTF-8",
    },
    TestCase {
        name: "binary_message",
        seed: TEST_SEED_1,
        message: MESSAGE_BINARY,
        description: "Message binaire avec octets speciaux",
    },
    TestCase {
        name: "alternate_seed",
        seed: TEST_SEED_2,
        message: MESSAGE_SHORT,
        description: "Message avec seed alternatif",
    },
    TestCase {
        name: "zero_seed",
        seed: TEST_SEED_ZEROS,
        message: MESSAGE_SHORT,
        description: "Message avec seed of zeros",
    },
    TestCase {
        name: "ones_seed",
        seed: TEST_SEED_ONES,
        message: MESSAGE_SHORT,
        description: "Message avec seed de uns",
    },
];

/// Vecteurs de test pour verification d'error
pub struct ErrorTestCase {
    pub name: &'static str,
    pub public_key: &'static [u8],
    pub message: &'static [u8],
    pub signature: &'static [u8],
    pub expected_error: &'static str,
    pub description: &'static str,
}

/// Cas d'error pour tests de verification
pub const ERROR_TEST_CASES: &[ErrorTestCase] = &[
    ErrorTestCase {
        name: "wrong_pk_size_too_short",
        public_key: &[0x00; 16], // Trop court (devrait be 32)
        message: MESSAGE_SHORT,
        signature: &[0x00; EXPECTED_SIG_SIZE_128S],
        expected_error: "InvalidPublicKeySize",
        description: "Key publique trop courte",
    },
    ErrorTestCase {
        name: "wrong_pk_size_too_long",
        public_key: &[0x00; 64], // Trop long (devrait be 32)
        message: MESSAGE_SHORT,
        signature: &[0x00; EXPECTED_SIG_SIZE_128S],
        expected_error: "InvalidPublicKeySize",
        description: "Key publique trop longue",
    },
    ErrorTestCase {
        name: "wrong_sig_size_too_short",
        public_key: EXPECTED_PK_128S,
        message: MESSAGE_SHORT,
        signature: &[0x00; 100], // Trop court
        expected_error: "InvalidSignatureSize",
        description: "Signature trop courte",
    },
    ErrorTestCase {
        name: "wrong_sig_size_too_long",
        public_key: EXPECTED_PK_128S,
        message: MESSAGE_SHORT,
        signature: &[0x00; EXPECTED_SIG_SIZE_128S + 100], // Trop long
        expected_error: "InvalidSignatureSize",
        description: "Signature trop longue",
    },
];

/// Data pour tests de performance
pub const BENCH_MESSAGE_SIZES: &[usize] = &[
    32,      // 1 bloc hash
    64,      // 2 blocs
    1024,    // 1 KB
    65536,   // 64 KB
    1048576, // 1 MB
];

/// Nombre d'iterations pour les tests de stress
pub const STRESS_TEST_ITERATIONS: usize = 1000;

/// Limite de temps pour les tests de performance (ms)
pub const PERF_TEST_TIMEOUT_MS: u64 = 5000;
