//! NIST KAT (Known Answer Test) support for Falcon.
//!
//! This module implements the NIST AES-256-CTR DRBG and SHA-1 hash
//! to reproduce the official NIST test vectors.

use alloc::vec::Vec;

/// AES S-box
const S: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
];

/// AES round constants
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
];

/// AES S-box with MixColumns pre-computed (for encryption)
const SSM0: [u32; 256] = [
    0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D, 0xFFF2F20D, 0xD66B6BBD,
    0xDE6F6FB1, 0x91C5C554, 0x60303050, 0x02010103, 0xCE6767A9, 0x562B2B7D,
    0xE7FEFE19, 0xB5D7D762, 0x4DABABE6, 0xEC76769A, 0x8FCACA45, 0x1F82829D,
    0x89C9C940, 0xFA7D7D87, 0xEFFAFA15, 0xB25959EB, 0x8E4747C9, 0xFBF0F00B,
    0x41ADADEC, 0xB3D4D467, 0x5FA2A2FD, 0x45AFAFEA, 0x239C9CBF, 0x53A4A4F7,
    0xE4727296, 0x9BC0C05B, 0x75B7B7C2, 0xE1FDFD1C, 0x3D9393AE, 0x4C26266A,
    0x6C36365A, 0x7E3F3F41, 0xF5F7F702, 0x83CCCC4F, 0x6834345C, 0x51A5A5F4,
    0xD1E5E534, 0xF9F1F108, 0xE2717193, 0xABD8D873, 0x62313153, 0x2A15153F,
    0x0804040C, 0x95C7C752, 0x46232365, 0x9DC3C35E, 0x30181828, 0x379696A1,
    0x0A05050F, 0x2F9A9AB5, 0x0E070709, 0x24121236, 0x1B80809B, 0xDFE2E23D,
    0xCDEBEB26, 0x4E272769, 0x7FB2B2CD, 0xEA75759F, 0x1209091B, 0x1D83839E,
    0x582C2C74, 0x341A1A2E, 0x361B1B2D, 0xDC6E6EB2, 0xB45A5AEE, 0x5BA0A0FB,
    0xA45252F6, 0x763B3B4D, 0xB7D6D661, 0x7DB3B3CE, 0x5229297B, 0xDDE3E33E,
    0x5E2F2F71, 0x13848497, 0xA65353F5, 0xB9D1D168, 0x00000000, 0xC1EDED2C,
    0x40202060, 0xE3FCFC1F, 0x79B1B1C8, 0xB65B5BED, 0xD46A6ABE, 0x8DCBCB46,
    0x67BEBED9, 0x7239394B, 0x944A4ADE, 0x984C4CD4, 0xB05858E8, 0x85CFCF4A,
    0xBBD0D06B, 0xC5EFEF2A, 0x4FAAAAE5, 0xEDFBFB16, 0x864343C5, 0x9A4D4DD7,
    0x66333355, 0x11858594, 0x8A4545CF, 0xE9F9F910, 0x04020206, 0xFE7F7F81,
    0xA05050F0, 0x783C3C44, 0x259F9FBA, 0x4BA8A8E3, 0xA25151F3, 0x5DA3A3FE,
    0x804040C0, 0x058F8F8A, 0x3F9292AD, 0x219D9DBC, 0x70383848, 0xF1F5F504,
    0x63BCBCDF, 0x77B6B6C1, 0xAFDADA75, 0x42212163, 0x20101030, 0xE5FFFF1A,
    0xFDF3F30E, 0xBFD2D26D, 0x81CDCD4C, 0x180C0C14, 0x26131335, 0xC3ECEC2F,
    0xBE5F5FE1, 0x359797A2, 0x884444CC, 0x2E171739, 0x93C4C457, 0x55A7A7F2,
    0xFC7E7E82, 0x7A3D3D47, 0xC86464AC, 0xBA5D5DE7, 0x3219192B, 0xE6737395,
    0xC06060A0, 0x19818198, 0x9E4F4FD1, 0xA3DCDC7F, 0x44222266, 0x542A2A7E,
    0x3B9090AB, 0x0B888883, 0x8C4646CA, 0xC7EEEE29, 0x6BB8B8D3, 0x2814143C,
    0xA7DEDE79, 0xBC5E5EE2, 0x160B0B1D, 0xADDBDB76, 0xDBE0E03B, 0x64323256,
    0x743A3A4E, 0x140A0A1E, 0x924949DB, 0x0C06060A, 0x4824246C, 0xB85C5CE4,
    0x9FC2C25D, 0xBDD3D36E, 0x43ACACEF, 0xC46262A6, 0x399191A8, 0x319595A4,
    0xD3E4E437, 0xF279798B, 0xD5E7E732, 0x8BC8C843, 0x6E373759, 0xDA6D6DB7,
    0x018D8D8C, 0xB1D5D564, 0x9C4E4ED2, 0x49A9A9E0, 0xD86C6CB4, 0xAC5656FA,
    0xF3F4F407, 0xCFEAEA25, 0xCA6565AF, 0xF47A7A8E, 0x47AEAEE9, 0x10080818,
    0x6FBABAD5, 0xF0787888, 0x4A25256F, 0x5C2E2E72, 0x381C1C24, 0x57A6A6F1,
    0x73B4B4C7, 0x97C6C651, 0xCBE8E823, 0xA1DDDD7C, 0xE874749C, 0x3E1F1F21,
    0x964B4BDD, 0x61BDBDDC, 0x0D8B8B86, 0x0F8A8A85, 0xE0707090, 0x7C3E3E42,
    0x71B5B5C4, 0xCC6666AA, 0x904848D8, 0x06030305, 0xF7F6F601, 0x1C0E0E12,
    0xC26161A3, 0x6A35355F, 0xAE5757F9, 0x69B9B9D0, 0x17868691, 0x99C1C158,
    0x3A1D1D27, 0x279E9EB9, 0xD9E1E138, 0xEBF8F813, 0x2B9898B3, 0x22111133,
    0xD26969BB, 0xA9D9D970, 0x078E8E89, 0x339494A7, 0x2D9B9BB6, 0x3C1E1E22,
    0x15878792, 0xC9E9E920, 0x87CECE49, 0xAA5555FF, 0x50282878, 0xA5DFDF7A,
    0x038C8C8F, 0x59A1A1F8, 0x09898980, 0x1A0D0D17, 0x65BFBFDA, 0xD7E6E631,
    0x844242C6, 0xD06868B8, 0x824141C3, 0x299999B0, 0x5A2D2D77, 0x1E0F0F11,
    0x7BB0B0CB, 0xA85454FC, 0x6DBBBBD6, 0x2C16163A,
];

#[inline]
fn dec32be(src: &[u8]) -> u32 {
    ((src[0] as u32) << 24)
        | ((src[1] as u32) << 16)
        | ((src[2] as u32) << 8)
        | (src[3] as u32)
}

#[inline]
fn enc32be(dst: &mut [u8], val: u32) {
    dst[0] = (val >> 24) as u8;
    dst[1] = (val >> 16) as u8;
    dst[2] = (val >> 8) as u8;
    dst[3] = val as u8;
}

#[inline]
fn sub_word(x: u32) -> u32 {
    ((S[(x >> 24) as usize] as u32) << 24)
        | ((S[((x >> 16) & 0xFF) as usize] as u32) << 16)
        | ((S[((x >> 8) & 0xFF) as usize] as u32) << 8)
        | (S[(x & 0xFF) as usize] as u32)
}

#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    (x << (32 - n)) | (x >> n)
}

fn aes256_keysched(key: &[u8]) -> [u32; 60] {
    let mut skey = [0u32; 60];

    for i in 0..8 {
        skey[i] = dec32be(&key[i * 4..]);
    }

    let mut j = 0usize;
    let mut k = 0usize;
    for i in 8..60 {
        let mut tmp = skey[i - 1];
        if j == 0 {
            tmp = (tmp << 8) | (tmp >> 24);
            tmp = sub_word(tmp) ^ RCON[k];
        } else if j == 4 {
            tmp = sub_word(tmp);
        }
        skey[i] = skey[i - 8] ^ tmp;
        j += 1;
        if j == 8 {
            j = 0;
            k += 1;
        }
    }

    skey
}

fn aes256_encrypt(skey: &[u32; 60], data: &mut [u8; 16]) {
    let mut s0 = dec32be(&data[0..]);
    let mut s1 = dec32be(&data[4..]);
    let mut s2 = dec32be(&data[8..]);
    let mut s3 = dec32be(&data[12..]);

    s0 ^= skey[0];
    s1 ^= skey[1];
    s2 ^= skey[2];
    s3 ^= skey[3];

    for u in 1..14 {
        let v0 = SSM0[(s0 >> 24) as usize]
            ^ rotr(SSM0[((s1 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s2 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s3 & 0xFF) as usize], 24);
        let v1 = SSM0[(s1 >> 24) as usize]
            ^ rotr(SSM0[((s2 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s3 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s0 & 0xFF) as usize], 24);
        let v2 = SSM0[(s2 >> 24) as usize]
            ^ rotr(SSM0[((s3 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s0 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s1 & 0xFF) as usize], 24);
        let v3 = SSM0[(s3 >> 24) as usize]
            ^ rotr(SSM0[((s0 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s1 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s2 & 0xFF) as usize], 24);

        s0 = v0 ^ skey[u * 4];
        s1 = v1 ^ skey[u * 4 + 1];
        s2 = v2 ^ skey[u * 4 + 2];
        s3 = v3 ^ skey[u * 4 + 3];
    }

    // Final round (no MixColumns)
    let v0 = ((S[(s0 >> 24) as usize] as u32) << 24)
        ^ ((S[((s1 >> 16) & 0xFF) as usize] as u32) << 16)
        ^ ((S[((s2 >> 8) & 0xFF) as usize] as u32) << 8)
        ^ (S[(s3 & 0xFF) as usize] as u32);
    let v1 = ((S[(s1 >> 24) as usize] as u32) << 24)
        ^ ((S[((s2 >> 16) & 0xFF) as usize] as u32) << 16)
        ^ ((S[((s3 >> 8) & 0xFF) as usize] as u32) << 8)
        ^ (S[(s0 & 0xFF) as usize] as u32);
    let v2 = ((S[(s2 >> 24) as usize] as u32) << 24)
        ^ ((S[((s3 >> 16) & 0xFF) as usize] as u32) << 16)
        ^ ((S[((s0 >> 8) & 0xFF) as usize] as u32) << 8)
        ^ (S[(s1 & 0xFF) as usize] as u32);
    let v3 = ((S[(s3 >> 24) as usize] as u32) << 24)
        ^ ((S[((s0 >> 16) & 0xFF) as usize] as u32) << 16)
        ^ ((S[((s1 >> 8) & 0xFF) as usize] as u32) << 8)
        ^ (S[(s2 & 0xFF) as usize] as u32);

    enc32be(&mut data[0..4], v0 ^ skey[56]);
    enc32be(&mut data[4..8], v1 ^ skey[57]);
    enc32be(&mut data[8..12], v2 ^ skey[58]);
    enc32be(&mut data[12..16], v3 ^ skey[59]);
}

/// NIST AES-256-CTR DRBG as used in PQC competition.
pub struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl NistDrbg {
    /// Create a new DRBG initialized with 48 bytes of entropy.
    pub fn new(entropy_input: &[u8; 48]) -> Self {
        let mut drbg = Self {
            key: [0u8; 32],
            v: [0u8; 16],
        };
        drbg.update(Some(entropy_input));
        drbg
    }

    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let skey = aes256_keysched(&self.key);
        let mut tmp = [0u8; 48];

        for i in 0..3 {
            // Increment V
            let mut carry = 1u16;
            for j in (0..16).rev() {
                let w = self.v[j] as u16 + carry;
                self.v[j] = w as u8;
                carry = w >> 8;
            }

            // Encrypt V
            let mut block = self.v;
            aes256_encrypt(&skey, &mut block);
            tmp[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }

        if let Some(data) = provided_data {
            for i in 0..48 {
                tmp[i] ^= data[i];
            }
        }

        self.key.copy_from_slice(&tmp[0..32]);
        self.v.copy_from_slice(&tmp[32..48]);
    }

    /// Generate random bytes.
    pub fn random_bytes(&mut self, output: &mut [u8]) {
        let mut remaining = output.len();
        let mut offset = 0;

        while remaining > 0 {
            // Increment V
            let mut carry = 1u16;
            for j in (0..16).rev() {
                let w = self.v[j] as u16 + carry;
                self.v[j] = w as u8;
                carry = w >> 8;
            }

            let skey = aes256_keysched(&self.key);
            let mut block = self.v;
            aes256_encrypt(&skey, &mut block);

            let clen = remaining.min(16);
            output[offset..offset + clen].copy_from_slice(&block[..clen]);
            offset += clen;
            remaining -= clen;
        }

        self.update(None);
    }

    /// Re-initialize the DRBG with new entropy.
    pub fn reseed(&mut self, entropy_input: &[u8; 48]) {
        self.key = [0u8; 32];
        self.v = [0u8; 16];
        self.update(Some(entropy_input));
    }

    /// Save the current state.
    pub fn save_state(&self) -> ([u8; 32], [u8; 16]) {
        (self.key, self.v)
    }

    /// Restore a previously saved state.
    pub fn restore_state(&mut self, state: ([u8; 32], [u8; 16])) {
        self.key = state.0;
        self.v = state.1;
    }
}

/// SHA-1 context for KAT hash computation.
pub struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha1 {
    const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: 0,
            buffer: [0u8; 64],
            buffer_len: 0,
        }
    }

    fn transform(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];

        for i in 0..16 {
            w[i] = ((block[i * 4] as u32) << 24)
                | ((block[i * 4 + 1] as u32) << 16)
                | ((block[i * 4 + 2] as u32) << 8)
                | (block[i * 4 + 3] as u32);
        }

        for i in 16..80 {
            let val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = val.rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), Self::K[0])
            } else if i < 40 {
                (b ^ c ^ d, Self::K[1])
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), Self::K[2])
            } else {
                (b ^ c ^ d, Self::K[3])
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        if self.buffer_len > 0 {
            let space = 64 - self.buffer_len;
            if data.len() < space {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }

            self.buffer[self.buffer_len..64].copy_from_slice(&data[..space]);
            let block: [u8; 64] = self.buffer;
            self.transform(&block);
            self.count += 64;
            self.buffer_len = 0;
            offset = space;
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.transform(&block);
            self.count += 64;
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let total_bits = (self.count + self.buffer_len as u64) * 8;

        // Padding
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block: [u8; 64] = self.buffer;
            self.transform(&block);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        // Length in bits (big-endian)
        self.buffer[56] = (total_bits >> 56) as u8;
        self.buffer[57] = (total_bits >> 48) as u8;
        self.buffer[58] = (total_bits >> 40) as u8;
        self.buffer[59] = (total_bits >> 32) as u8;
        self.buffer[60] = (total_bits >> 24) as u8;
        self.buffer[61] = (total_bits >> 16) as u8;
        self.buffer[62] = (total_bits >> 8) as u8;
        self.buffer[63] = total_bits as u8;

        let block: [u8; 64] = self.buffer;
        self.transform(&block);

        let mut output = [0u8; 20];
        for i in 0..5 {
            output[i * 4] = (self.state[i] >> 24) as u8;
            output[i * 4 + 1] = (self.state[i] >> 16) as u8;
            output[i * 4 + 2] = (self.state[i] >> 8) as u8;
            output[i * 4 + 3] = self.state[i] as u8;
        }

        output
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a line for KAT output: "prefix\n"
pub fn format_line(sha: &mut Sha1, line: &str) {
    sha.update(line.as_bytes());
    sha.update(b"\n");
}

/// Format a line with integer: "prefix<int>\n"
pub fn format_line_with_int(sha: &mut Sha1, prefix: &str, value: u32) {
    sha.update(prefix.as_bytes());

    // Convert integer to string
    let mut buf = [0u8; 10];
    let mut n = value;
    let mut i = buf.len();

    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }

    sha.update(&buf[i..]);
    sha.update(b"\n");
}

/// Format a line with hex data: "prefix<hex>\n"
pub fn format_line_with_hex(sha: &mut Sha1, prefix: &str, data: &[u8]) {
    sha.update(prefix.as_bytes());

    const HEX_CHARS: &[u8] = b"0123456789ABCDEF";
    for &byte in data {
        sha.update(&[HEX_CHARS[(byte >> 4) as usize], HEX_CHARS[(byte & 0x0F) as usize]]);
    }

    sha.update(b"\n");
}

/// Convert hex string to bytes.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.as_bytes();
    let mut result = Vec::with_capacity(hex.len() / 2);

    let mut i = 0;
    while i < hex.len() {
        let high = match hex[i] {
            b'0'..=b'9' => hex[i] - b'0',
            b'a'..=b'f' => hex[i] - b'a' + 10,
            b'A'..=b'F' => hex[i] - b'A' + 10,
            _ => {
                i += 1;
                continue;
            }
        };

        i += 1;
        if i >= hex.len() {
            break;
        }

        let low = match hex[i] {
            b'0'..=b'9' => hex[i] - b'0',
            b'a'..=b'f' => hex[i] - b'a' + 10,
            b'A'..=b'F' => hex[i] - b'A' + 10,
            _ => continue,
        };

        result.push((high << 4) | low);
        i += 1;
    }

    result
}

/// Internal Falcon operations for NIST KAT testing.
///
/// These functions provide direct access to the internal Falcon functions,
/// bypassing the public API. This is needed for byte-exact NIST KAT reproduction.
pub mod internal {
    use alloc::vec;
    use alloc::vec::Vec;

    /// Internal SHAKE256 context wrapper.
    pub struct InnerShake256 {
        ctx: falcon_sys::inner_shake256_context,
    }

    impl InnerShake256 {
        /// Create a new internal SHAKE256 context.
        pub fn new() -> Self {
            let mut ctx = falcon_sys::inner_shake256_context::default();
            unsafe {
                falcon_sys::falcon_inner_i_shake256_init(&mut ctx);
            }
            Self { ctx }
        }

        /// Inject (absorb) data into the context.
        pub fn inject(&mut self, data: &[u8]) {
            unsafe {
                falcon_sys::falcon_inner_i_shake256_inject(&mut self.ctx, data.as_ptr(), data.len());
            }
        }

        /// Flip the context to output mode.
        pub fn flip(&mut self) {
            unsafe {
                falcon_sys::falcon_inner_i_shake256_flip(&mut self.ctx);
            }
        }

        /// Extract (squeeze) bytes from the context.
        pub fn extract(&mut self, output: &mut [u8]) {
            unsafe {
                falcon_sys::falcon_inner_i_shake256_extract(&mut self.ctx, output.as_mut_ptr(), output.len());
            }
        }

        /// Get raw context for FFI calls.
        pub fn as_mut_ptr(&mut self) -> *mut falcon_sys::inner_shake256_context {
            &mut self.ctx
        }
    }

    impl Default for InnerShake256 {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Raw Falcon key material.
    pub struct RawKeyMaterial {
        /// f polynomial (n coefficients)
        pub f: Vec<i8>,
        /// g polynomial (n coefficients)
        pub g: Vec<i8>,
        /// F polynomial (n coefficients)
        pub f_cap: Vec<i8>,
        /// G polynomial (n coefficients, can be computed from others)
        pub g_cap: Vec<i8>,
        /// Public key polynomial h (n coefficients)
        pub h: Vec<u16>,
        /// Degree logarithm
        pub logn: u32,
    }

    impl RawKeyMaterial {
        /// Generate raw key material using internal keygen.
        pub fn generate(rng: &mut InnerShake256, logn: u32) -> Self {
            let n = 1usize << logn;

            let mut f = vec![0i8; n];
            let mut g = vec![0i8; n];
            let mut f_cap = vec![0i8; n];
            let mut g_cap = vec![0i8; n];
            let mut h = vec![0u16; n];

            // Allocate temporary buffer (must be 64-bit aligned)
            let tmp_size = falcon_sys::tmpsize_keygen(logn);
            let mut tmp = vec![0u64; (tmp_size + 7) / 8];
            let tmp_ptr = tmp.as_mut_ptr() as *mut u8;

            unsafe {
                falcon_sys::falcon_inner_keygen(
                    rng.as_mut_ptr(),
                    f.as_mut_ptr(),
                    g.as_mut_ptr(),
                    f_cap.as_mut_ptr(),
                    g_cap.as_mut_ptr(),
                    h.as_mut_ptr(),
                    logn,
                    tmp_ptr,
                );
            }

            Self {
                f,
                g,
                f_cap,
                g_cap,
                h,
                logn,
            }
        }

        /// Encode the private key in Falcon format.
        pub fn encode_private_key(&self) -> Vec<u8> {
            let max_fg_bits = get_max_fg_bits(self.logn);
            let max_fg_cap_bits = get_max_fg_cap_bits(self.logn);
            let sk_len = falcon_sys::privkey_size(self.logn);
            let mut sk = vec![0u8; sk_len];

            sk[0] = 0x50 + self.logn as u8;
            let mut u = 1;

            // Encode f
            let v = unsafe {
                falcon_sys::falcon_inner_trim_i8_encode(
                    sk.as_mut_ptr().add(u),
                    sk_len - u,
                    self.f.as_ptr(),
                    self.logn,
                    max_fg_bits,
                )
            };
            assert!(v != 0, "Failed to encode f");
            u += v;

            // Encode g
            let v = unsafe {
                falcon_sys::falcon_inner_trim_i8_encode(
                    sk.as_mut_ptr().add(u),
                    sk_len - u,
                    self.g.as_ptr(),
                    self.logn,
                    max_fg_bits,
                )
            };
            assert!(v != 0, "Failed to encode g");
            u += v;

            // Encode F
            let v = unsafe {
                falcon_sys::falcon_inner_trim_i8_encode(
                    sk.as_mut_ptr().add(u),
                    sk_len - u,
                    self.f_cap.as_ptr(),
                    self.logn,
                    max_fg_cap_bits,
                )
            };
            assert!(v != 0, "Failed to encode F");
            u += v;

            assert_eq!(u, sk_len, "Wrong private key length");
            sk
        }

        /// Encode the public key in Falcon format.
        pub fn encode_public_key(&self) -> Vec<u8> {
            let pk_len = falcon_sys::pubkey_size(self.logn);
            let mut pk = vec![0u8; pk_len];

            pk[0] = self.logn as u8;

            let v = unsafe {
                falcon_sys::falcon_inner_modq_encode(
                    pk.as_mut_ptr().add(1),
                    pk_len - 1,
                    self.h.as_ptr(),
                    self.logn,
                )
            };

            assert_eq!(1 + v, pk_len, "Wrong public key length");
            pk
        }

        /// Sign a hashed message using internal sign_dyn.
        pub fn sign(&self, hm: &[u16], rng: &mut InnerShake256) -> Vec<i16> {
            let n = 1usize << self.logn;
            let mut sig = vec![0i16; n];

            // Allocate temporary buffer (78*n bytes, 64-bit aligned)
            let tmp_size = falcon_sys::tmpsize_signdyn(self.logn);
            let mut tmp = vec![0u64; (tmp_size + 7) / 8];
            let tmp_ptr = tmp.as_mut_ptr() as *mut u8;

            unsafe {
                falcon_sys::falcon_inner_sign_dyn(
                    sig.as_mut_ptr(),
                    rng.as_mut_ptr(),
                    self.f.as_ptr(),
                    self.g.as_ptr(),
                    self.f_cap.as_ptr(),
                    self.g_cap.as_ptr(),
                    hm.as_ptr(),
                    self.logn,
                    tmp_ptr,
                );
            }

            sig
        }
    }

    /// Hash a message to a point using internal hash_to_point_vartime.
    pub fn hash_to_point(sc: &mut InnerShake256, logn: u32) -> Vec<u16> {
        let n = 1usize << logn;
        let mut x = vec![0u16; n];

        unsafe {
            falcon_sys::falcon_inner_hash_to_point_vartime(sc.as_mut_ptr(), x.as_mut_ptr(), logn);
        }

        x
    }

    /// Compress-encode a raw signature.
    pub fn comp_encode(sig: &[i16], logn: u32) -> Option<Vec<u8>> {
        let max_out_len = falcon_sys::sig_compressed_maxsize(logn);
        let mut out = vec![0u8; max_out_len];

        let len = unsafe {
            falcon_sys::falcon_inner_comp_encode(out.as_mut_ptr(), max_out_len, sig.as_ptr(), logn)
        };

        if len == 0 {
            None
        } else {
            out.truncate(len);
            Some(out)
        }
    }

    /// Get max_fg_bits for a given logn.
    ///
    /// Values from the C implementation:
    /// - logn=9 (Falcon-512): 6 bits
    /// - logn=10 (Falcon-1024): 5 bits
    pub fn get_max_fg_bits(logn: u32) -> u32 {
        // These are the values from the C implementation (codec.c)
        // The values are indexed by logn from 0 to 10
        const MAX_FG_BITS: [u32; 11] = [0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5];
        MAX_FG_BITS[logn as usize]
    }

    /// Get max_FG_bits for a given logn.
    ///
    /// For F and G polynomials, all values are 8 bits.
    pub fn get_max_fg_cap_bits(logn: u32) -> u32 {
        // These are the values from the C implementation (codec.c)
        const MAX_FG_CAP_BITS: [u32; 11] = [0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];
        MAX_FG_CAP_BITS[logn as usize]
    }

    /// Verify that internal keygen produces keys matching the public API.
    #[cfg(test)]
    pub fn verify_keygen_match(seed: &[u8; 48], logn: u32) -> (bool, bool) {
        use crate::{Falcon1024, Falcon512, KeyPair};

        // Generate with internal keygen
        let mut rng = InnerShake256::new();
        rng.inject(seed);
        rng.flip();
        let keys = RawKeyMaterial::generate(&mut rng, logn);
        let internal_pk = keys.encode_public_key();
        let internal_sk = keys.encode_private_key();

        // Generate with public API
        let (public_pk, public_sk) = if logn == 9 {
            let kp = KeyPair::<Falcon512>::generate_from_seed(seed).unwrap();
            (
                kp.public_key().as_bytes().to_vec(),
                kp.private_key().as_bytes().to_vec(),
            )
        } else {
            let kp = KeyPair::<Falcon1024>::generate_from_seed(seed).unwrap();
            (
                kp.public_key().as_bytes().to_vec(),
                kp.private_key().as_bytes().to_vec(),
            )
        };

        (internal_pk == public_pk, internal_sk == public_sk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_encrypt() {
        // NIST AES-256 test vector
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let plaintext = hex_to_bytes("00112233445566778899aabbccddeeff");
        let expected = hex_to_bytes("8ea2b7ca516745bfeafc49904b496089");

        let skey = aes256_keysched(&key);
        let mut data: [u8; 16] = plaintext.try_into().unwrap();
        aes256_encrypt(&skey, &mut data);

        assert_eq!(&data[..], &expected[..]);
    }

    #[test]
    fn test_nist_drbg() {
        // Test that DRBG produces deterministic output
        let entropy: [u8; 48] = core::array::from_fn(|i| i as u8);
        let mut drbg = NistDrbg::new(&entropy);

        let mut out1 = [0u8; 48];
        drbg.random_bytes(&mut out1);

        // Reset and generate again
        let mut drbg2 = NistDrbg::new(&entropy);
        let mut out2 = [0u8; 48];
        drbg2.random_bytes(&mut out2);

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_internal_keygen_matches_public_api() {
        let seed = [0x42u8; 48];

        // Test Falcon-512
        let (pk_match, sk_match) = internal::verify_keygen_match(&seed, 9);
        assert!(pk_match, "Internal PK should match public API for Falcon-512");
        assert!(sk_match, "Internal SK should match public API for Falcon-512");

        // Test Falcon-1024
        let (pk_match, sk_match) = internal::verify_keygen_match(&seed, 10);
        assert!(pk_match, "Internal PK should match public API for Falcon-1024");
        assert!(sk_match, "Internal SK should match public API for Falcon-1024");
    }

    #[test]
    fn test_sha1() {
        // Test vector: SHA1("")
        let sha = Sha1::new();
        let hash = sha.finalize();
        let expected = hex_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(&hash[..], &expected[..]);

        // Test vector: SHA1("abc")
        let mut sha = Sha1::new();
        sha.update(b"abc");
        let hash = sha.finalize();
        let expected = hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(&hash[..], &expected[..]);

        // Test vector: SHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        let mut sha = Sha1::new();
        sha.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let hash = sha.finalize();
        let expected = hex_to_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        assert_eq!(&hash[..], &expected[..]);
    }
}
