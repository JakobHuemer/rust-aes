
fn main() {
    // get input from the first cli argument
    let args: Vec<String> = std::env::args().collect();
    let input = &args[1];
    let input: Vec<u8> = input.as_bytes().to_vec();


    print_hex(&input);
    println!("");

    println!("----------------");

    let cypher_key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let cypher = aes128_ecb(&cypher_key, input);

    print_hex(&cypher);

}

fn aes128_ecb(key: &[u8; 16], plain_text: Vec<u8>) -> Vec<u8> {
    let mut cypher = Vec::new();

    let rounds = (plain_text.len() as f32 / 16.0).ceil() as usize;

    for i in 0..rounds {
        if i == rounds - 1 {
            let mut block: Vec<u8> = plain_text[i * 16..plain_text.len()].to_vec(); // Convert the slice to a Vec<u8>
            pkcs7_pad(&mut block, 16);
            let mut block_arr: [u8; 16] = block.try_into().unwrap();
            block_arr = aes128_ecb_singleblock(&key, &block_arr);
            cypher.append(&mut (block_arr.to_vec()));
        } else {
            // ensure that the slice is 16 bytes long
            let mut block: [u8; 16] = plain_text[i * 16..(i + 1) * 16].try_into().unwrap();
            block = aes128_ecb_singleblock(key, &block);
            cypher.append(&mut (block.to_vec()))
        }
    }

    cypher
}

fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    for _ in 0..padding_len {
        data.push(padding_len as u8);
    }
}

fn aes128_ecb_singleblock(key: &[u8; 16], plain_text: &[u8; 16]) -> [u8; 16] {
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

    let row = (t >> 4) as usize;
    let col = (t & 0x0F) as usize;
    AES_S_BOX[row][col]
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

    /*
     *
     * d4 e0 b8 1e
     * bf b4 41 27
     * 5d 52 11 98
     * 30 ae f1 e5
     *
     */

    // first: 2 * d4 + 3 * bf + 1 * 5d + 1 * 30
    // second: 1 * d4 + 2 * bf + 3 * 5d + 1 * 30
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

fn print_hex(t: &[u8]) {
    for i in 0..t.len() {
        print!("{:02x} ", t[i]);
        if i % 4 == 3 {
            println!("");
        }
    }
}

fn print_vert(t: &[u8; 16]) {
    for i in 0..4 {
        // i for 4*i
        for j in 0..4 {
            print!("{:02x} ", t[4 * j + i]);
        }
        println!("");
    }
}
