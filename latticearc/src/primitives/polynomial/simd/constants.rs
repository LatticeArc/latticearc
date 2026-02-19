//! ML-KEM constants and NTT twiddle factors
//!
//! Contains parameters for lattice-based cryptography operations
//! in the ring R_q = Z_q[X]/(X^256 + 1) with q = 3329.

/// Polynomial degree for ML-KEM
pub const MLKEM_N: usize = 256;

/// Modulus q = 3329
pub const MLKEM_Q: i32 = 3329;

/// Montgomery constant: 2^16 mod q
pub const MONT: i32 = 2285;

/// Montgomery inverse: q^-1 mod 2^16
pub const QINV: i32 = -3327;

/// Montgomery squared: mont^2 mod q
pub const MONT_SQ: i32 = 1353;

/// Montgomery squared inverse: mont^2 * inv128 mod q
pub const MONT_SQ_INV: i32 = 1441;

/// Precomputed twiddle factors for NTT
pub const ZETAS: [i32; 128] = [
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628
];
