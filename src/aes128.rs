use rand::{thread_rng, Rng};
use std::cmp::min;
use std::io::stdout;

pub struct AES128 {
    pub key: [u8; 16],
    pub iv_vector: [u8; 16],
    pub nonce: [u8; 16],
}

pub struct CTRPacket {
    pub nonce: [u8; 16],
    pub counter: u128,
    pub cypher: [u8; 16],
}

impl CTRPacket {
    pub fn new() -> CTRPacket {
        CTRPacket {
            nonce: [0; 16],
            counter: 0,
            cypher: [0; 16],
        }
    }
}

impl AES128 {
    pub fn new() -> AES128 {
        let mut a = AES128 {
            key: [0; 16],
            iv_vector: [0; 16],
            nonce: [0; 16],
        };
        a.key = Self::generate_random_128_bits();
        a.iv_vector = Self::generate_random_128_bits();
        a.nonce = Self::generate_random_128_bits();
        a
    }

    pub fn encrypt_ecb(&self, plain_text: &Vec<u8>) -> Vec<u8> {
        let mut cypher = Vec::new();

        let rounds = (plain_text.len() as f32 / 16.0).ceil() as usize;

        for i in 0..rounds {
            if i == rounds - 1 {
                let mut block: Vec<u8> = plain_text[i * 16..plain_text.len()].to_vec(); // Convert the slice to a Vec<u8>
                pkcs7_pad(&mut block, 16);
                if block.len() > 16 {
                    let mut block1: [u8; 16] = block[..16].try_into().unwrap();
                    let mut block2: [u8; 16] = block[16..].try_into().unwrap();
                    let block_arr2 = aes128_encrypt_block(&self.key, &block2);
                    let block_arr1 = aes128_encrypt_block(&self.key, &block1);
                    cypher.append(&mut (block_arr1.to_vec()));
                    cypher.append(&mut (block_arr2.to_vec()));
                } else {
                    let mut block: [u8; 16] = block.try_into().unwrap();
                    block = aes128_encrypt_block(&self.key, &block);
                    cypher.append(&mut (block.to_vec()));
                }
            } else {
                // ensure that the slice is 16 bytes long
                let mut block: [u8; 16] = plain_text[i * 16..(i + 1) * 16].try_into().unwrap();
                block = aes128_encrypt_block(&self.key, &block);
                cypher.append(&mut (block.to_vec()))
            }
        }

        cypher
    }

    pub fn decrypt_ecb(&self, cypher_text: &Vec<u8>) -> Vec<u8> {
        let mut plain_text = Vec::new();

        let rounds = (cypher_text.len() as f32 / 16.0).ceil() as usize;

        for i in 0..rounds {
            let mut block: [u8; 16] = cypher_text[i * 16..min((i + 1) * 16, cypher_text.len())]
                .try_into()
                .unwrap();

            block = aes128_decrypt_block(&self.key, &block);
            plain_text.append(&mut (block.to_vec()));
        }

        pkcs7_unpad(&mut plain_text);

        plain_text
    }

    pub fn encrypt_cbc(&self, plain_text: &Vec<u8>) -> Vec<u8> {
        // TODO: last 32 bytes (2 blocks) are wrong

        let mut cypher: Vec<u8> = Vec::new();
        let mut cypher_blocks: Vec<[u8; 16]> = Vec::new();

        let iv = self.iv_vector;
        let key = self.key;
        let rounds = ((plain_text.len() as f32 + 1.0) / 16.0).ceil() as usize;

        let mut plain_text_blocks: Vec<[u8; 16]> = Vec::new();

        for i in 0..rounds {
            if i == rounds - 1 {
                // pad block and append
                let mut block_vec: Vec<u8> = plain_text[i * 16..plain_text.len()].to_vec();
                pkcs7_pad(&mut block_vec, 16);

                let block: [u8; 16] = block_vec.try_into().unwrap();
                plain_text_blocks.push(block);
            } else {
                let block: [u8; 16] = plain_text[i * 16..(i + 1) * 16].try_into().unwrap();
                plain_text_blocks.push(block)
            }
        }

        let mut prev_cypher: [u8; 16] = iv;

        for el in plain_text_blocks.iter() {
            let mut plain_block = el.clone();

            for i in 0..16 {
                plain_block[i] ^= prev_cypher[i];
            }

            let encrypted_block = aes128_encrypt_block(&key, &plain_block);
            cypher_blocks.push(encrypted_block);
            prev_cypher = encrypted_block;
        }

        for el in cypher_blocks.iter_mut() {
            cypher.append(&mut (el.to_vec()));
        }

        cypher
    }

    pub fn decrypt_cbc(&self, cypher_text: &Vec<u8>) -> Vec<u8> {
        let mut plain_text: Vec<u8> = Vec::new();
        let mut cypher_blocks: Vec<[u8; 16]> = Vec::new();
        let mut plain_blocks: Vec<[u8; 16]> = Vec::new();

        let iv = self.iv_vector;
        let key = self.key;
        let rounds = (cypher_text.len() as f32 / 16.0).ceil() as usize;
        let mut prev_cypher: [u8; 16] = iv;

        for i in 0..rounds {
            cypher_blocks.push(
                cypher_text[i * 16..min((i + 1) * 16, cypher_text.len())]
                    .try_into()
                    .unwrap(),
            )
        }

        // for i in 0..rounds {
        //     print_as_hex(&cypher_blocks[i].to_vec());
        // }

        for i in 0..rounds {
            let mut block = cypher_blocks[i].clone();

            block = aes128_decrypt_block(&key, &block);

            for i in 0..16 {
                block[i] ^= prev_cypher[i];
            }

            plain_blocks.push(block);

            prev_cypher = cypher_blocks[i];
        }

        for i in 0..rounds {
            plain_text.append(&mut (plain_blocks[i].to_vec()));
        }

        pkcs7_unpad(&mut plain_text);

        plain_text
    }

    pub fn encrypt_ctr(&self, cypher_text: &Vec<u8>) -> Vec<CTRPacket> {
        let packets: Vec<CTRPacket> = Vec::new();
        let mut cypher_blocks: Vec<[u8; 16]> = Vec::new();
        let rounds = (cypher_text.len() as f32 / 16.0).ceil() as usize;
        let nonce = self.nonce;
        let mut counter: u128 = 0;

        for i in 0..rounds {
            let block: [u8; 16] = cypher_text[i * 16..(i + 1) * 16].try_into().unwrap();
            let mut packet = CTRPacket::new();
            packet.nonce = nonce;
            packet.counter = counter;
            packet.cypher = block.clone();

            counter += 1;
        }

        packets
    }

    // TODO: CBC including key stealing

    pub fn encrypt_cbc_steal(&self, plain_text: &Vec<u8>) -> Vec<u8> {

        let mut cypher: Vec<u8> = Vec::new();
        let mut cypher_blocks: Vec<[u8; 16]> = Vec::new();

        let iv = self.iv_vector;
        let key = self.key;
        let rounds = ((plain_text.len() as f32 + 1.0) / 16.0).ceil() as usize;

        let mut plain_text_blocks: Vec<[u8; 16]> = Vec::new();

        for i in 0..rounds {
            if i == rounds - 1 {
                // pad block and append
                let mut block_vec: Vec<u8> = plain_text[i * 16..plain_text.len()].to_vec();
                zero_pad(&mut block_vec, 16);

                let block: [u8; 16] = block_vec.try_into().unwrap();
                plain_text_blocks.push(block);
            } else {
                let block: [u8; 16] = plain_text[i * 16..(i + 1) * 16].try_into().unwrap();
                plain_text_blocks.push(block)
            }
        }

        let mut prev_cypher: [u8; 16] = iv;

        for el in plain_text_blocks.iter() {
            let mut plain_block = el.clone();

            for i in 0..16 {
                plain_block[i] ^= prev_cypher[i];
            }

            let encrypted_block = aes128_encrypt_block(&key, &plain_block);
            cypher_blocks.push(encrypted_block);
            prev_cypher = encrypted_block;
        }

        // swap last two cypher blocks
        // TODO: See comment above

        for el in cypher_blocks.iter_mut() {
            cypher.append(&mut (el.to_vec()));
        }


        cypher
    }

    pub fn generate_random_128_bits() -> [u8; 16] {
        let mut r = [0u8; 16];
        thread_rng().fill(&mut r);
        r
    }
}

pub fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    for _ in 0..padding_len {
        data.push(padding_len as u8);
    }
}

// remove pkcs7 padding
pub fn pkcs7_unpad(data: &mut Vec<u8>) {
    if data.len() == 0 {
        return;
    }
    let padding_len = data[data.len() - 1] as usize;
    data.truncate(data.len() - padding_len);
}

fn zero_pad(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    for _ in 0..padding_len {
        data.push(0);
    }
}

fn aes128_decrypt_block(key: &[u8; 16], cypher_text: &[u8; 16]) -> [u8; 16] {
    let mut r = cypher_text.clone();
    let mut round_key = key.clone();
    let mut round_keys: Vec<[u8; 16]> = Vec::new();
    round_keys.push(round_key);
    for i in 0..10 {
        round_key = get_round_key(&round_key, i);
        round_keys.push(round_key);
    }

    add_round_key(&mut r, &round_keys[10]);

    reverse_shift_rows(&mut r);

    reverse_sub_bytes(&mut r);

    for i in 0..9 {
        add_round_key(&mut r, &round_keys[9 - i]);

        reverse_mix_columns(&mut r);
        reverse_shift_rows(&mut r);
        reverse_sub_bytes(&mut r);
    }

    add_round_key(&mut r, &round_keys[0]);

    r
}

fn aes128_encrypt_block(key: &[u8; 16], plain_text: &[u8; 16]) -> [u8; 16] {
    // Perform AES-128 encryption here

    let mut r: [u8; 16] = plain_text.clone();
    let mut round_key = key.clone();

    add_round_key(&mut r, &key);

    for i in 0..9 {
        sub_bytes(&mut r);
        shift_rows(&mut r);

        mix_columns(&mut r);

        round_key = get_round_key(&round_key, i);
        add_round_key(&mut r, &round_key);
    }
    round_key = get_round_key(&round_key, 9);
    sub_bytes(&mut r);
    shift_rows(&mut r);
    add_round_key(&mut r, &round_key);
    return r;
}

fn add_round_key(t: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        t[i] = t[i] ^ round_key[i];
    }
}

fn sub_bytes(t: &mut [u8]) {
    for i in 0..t.len() {
        t[i] = s_box(t[i]);
    }
}

fn reverse_sub_bytes(t: &mut [u8]) {
    for i in 0..t.len() {
        t[i] = reverse_s_box(t[i]);
    }
}

fn s_box(t: u8) -> u8 {
    const AES_S_BOX: [[u8; 16]; 16] = [
        [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ],
        [
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
            0x72, 0xc0,
        ],
        [
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8,
            0x31, 0x15,
        ],
        [
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27,
            0xb2, 0x75,
        ],
        [
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
            0x2f, 0x84,
        ],
        [
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c,
            0x58, 0xcf,
        ],
        [
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8,
        ],
        [
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2,
        ],
        [
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d,
            0x19, 0x73,
        ],
        [
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e,
            0x0b, 0xdb,
        ],
        [
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95,
            0xe4, 0x79,
        ],
        [
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
            0xae, 0x08,
        ],
        [
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd,
            0x8b, 0x8a,
        ],
        [
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1,
            0x1d, 0x9e,
        ],
        [
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf,
        ],
        [
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54,
            0xbb, 0x16,
        ],
    ];

    s_box_from(t, &AES_S_BOX)
}

fn reverse_s_box(t: u8) -> u8 {
    const AES_S_BOX: [[u8; 16]; 16] = [
        [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb,
        ],
        [
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
            0xe9, 0xcb,
        ],
        [
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa,
            0xc3, 0x4e,
        ],
        [
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b,
            0xd1, 0x25,
        ],
        [
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
            0xb6, 0x92,
        ],
        [
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d,
            0x9d, 0x84,
        ],
        [
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06,
        ],
        [
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
            0x8a, 0x6b,
        ],
        [
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4,
            0xe6, 0x73,
        ],
        [
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75,
            0xdf, 0x6e,
        ],
        [
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18,
            0xbe, 0x1b,
        ],
        [
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd,
            0x5a, 0xf4,
        ],
        [
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80,
            0xec, 0x5f,
        ],
        [
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9,
            0x9c, 0xef,
        ],
        [
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
            0x99, 0x61,
        ],
        [
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21,
            0x0c, 0x7d,
        ],
    ];

    s_box_from(t, &AES_S_BOX)
}

fn s_box_from(t: u8, aes_box: &[[u8; 16]; 16]) -> u8 {
    let row = (t >> 4) as usize;
    let col = (t & 0x0F) as usize;
    aes_box[row][col]
}

fn shift_rows(t: &mut [u8; 16]) {
    // Shift second row by 1 position to the left

    swp(t, 1, 5);
    swp(t, 5, 9);
    swp(t, 9, 13);

    // shift thrid row
    swp(t, 2, 10);
    swp(t, 6, 14);

    // shift last row
    swp(t, 11, 15);
    swp(t, 7, 11);
    swp(t, 3, 7);
}

fn reverse_shift_rows(t: &mut [u8; 16]) {
    // reverse of shift_rows
    swp(t, 3, 7);
    swp(t, 7, 11);
    swp(t, 11, 15);

    swp(t, 6, 14);
    swp(t, 2, 10);

    swp(t, 9, 13);
    swp(t, 5, 9);
    swp(t, 1, 5);
}

fn swp(t: &mut [u8; 16], i: usize, j: usize) {
    let temp = t[i];
    t[i] = t[j];
    t[j] = temp;
}

fn mix_columns(t: &mut [u8; 16]) {
    let m: [[u8; 4]; 4] = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ];

    mix_columns_with(t, &m);
}

fn reverse_mix_columns(t: &mut [u8; 16]) {
    // how does aes reverse mix columns work?
    // 1. multiply each column by the inverse of the matrix
    // 2. the inverse of the matrix is
    let m: [[u8; 4]; 4] = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e],
    ];

    mix_columns_with(t, &m);
}

fn mix_columns_with(t: &mut [u8; 16], m: &[[u8; 4]; 4]) {
    let mut temp: [u8; 16] = t.clone();

    for i in 0usize..4usize {
        // i used as offset for t by 4*i

        for j in 0usize..4usize {
            // j used as offset for mm by j

            let mut temp_val: u32 = 0;
            for k in 0usize..4usize {
                // j for sub m and sub t

                temp_val ^= gf_multiply(m[j][k], t[4 * i + k]) as u32;
            }

            temp[i * 4 + j] = temp_val as u8;
        }
    }

    for i in 0usize..16 {
        t[i] = temp[i];
    }
}

fn gf_multiply(a: u8, b: u8) -> u8 {
    let mut result = 0;
    let mut b = b;
    let mut a = a;

    while a != 0 {
        if a & 1 != 0 {
            result ^= b;
        }

        let high_bit_set = b & 0x80 != 0;
        b <<= 1;

        if high_bit_set {
            b ^= 0x1B; // This is the irreducible polynomial for GF(2^8)
        }

        a >>= 1;
    }

    result
}

// Key schedule

fn get_round_key(key: &[u8; 16], round: u8) -> [u8; 16] {
    let mut new_key: [u8; 16] = key.clone();

    // rotate by one
    swp(&mut new_key, 12, 13);
    swp(&mut new_key, 13, 14);
    swp(&mut new_key, 14, 15);

    new_key[12] = s_box(new_key[12]);
    new_key[13] = s_box(new_key[13]);
    new_key[14] = s_box(new_key[14]);
    new_key[15] = s_box(new_key[15]);

    for i in 0usize..4usize {
        new_key[i + 12] ^= key[i];
        new_key[i + 12] ^= rcon(round)[i];
    }

    for i in 0usize..4usize {
        new_key[i] = new_key[12 + i];
    }

    for i in 1usize..4usize {
        for j in 0usize..4usize {
            new_key[4 * i + j] = new_key[(i - 1) * 4 + j] ^ key[4 * i + j];
        }
    }

    new_key
}

fn rcon(n: u8) -> [u8; 4] {
    const RCON: [[u8; 4]; 10] = [
        [0x01, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00],
        [0x08, 0x00, 0x00, 0x00],
        [0x10, 0x00, 0x00, 0x00],
        [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00],
        [0x80, 0x00, 0x00, 0x00],
        [0x1b, 0x00, 0x00, 0x00],
        [0x36, 0x00, 0x00, 0x00],
    ];

    RCON[n as usize]
}

pub fn print_hex(t: &[u8]) {
    for i in 0..t.len() {
        print!("{:02x} ", t[i]);
        if i % 4 == 3 {
            println!("");
        }
    }
    println!("")
}

pub fn print_vert(t: &[u8; 16]) {
    for i in 0..4 {
        // i for 4*i
        for j in 0..4 {
            print!("{:02x} ", t[4 * j + i]);
        }
        println!("");
    }
}

fn hex_as_utf8(hex: &Vec<u8>) -> &str {
    std::str::from_utf8(hex).unwrap()
}

fn print_as_hex(hex: &Vec<u8>) {
    for i in 0..hex.len() {
        print!("{:02x}", hex[i]);
    }
    println!();
}
