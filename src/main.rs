mod aes128;
use std::f32::consts::E;

use aes128::AES128;

mod rsa_client;
use base64::Engine;
use num::{BigUint, Float, Num};
use num_bigint::{RandBigInt, RandomBits};
use rand::{thread_rng, Rng};
use rsa_client::{is_prime, RsaClient};
/**
 *
 * USAGE: aes128 [MODE] [args]
 *
 * MODE:
 *  fe - File encrypt
 *  te - Text encrypt
 *  fd - File decrypt
 *  td - Text decrypt
 *
 * args:
 *  -i=FILE, input file
 *  -o=FILE, output file
 *  -t=TEXT, text to en-, decrypt
 *
 */

fn main() {
    // let input = *b"lorem ipsum dolor sit amet, consectetur adipiscing elit. \
    // Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, \
    // ultricies sed, dolor. Cras elementum ultrices diam. Maecenas ligula massa, \
    // varius a, semper congue, euismod non, mi. Proin porttitor, orci nec nonummy \
    // molestie, enim est eleifend mi, non fermentum diam nisl sit amet erat. Duis \
    // semper. Duis arcu massa, scelerisque vitae, consequat isn, pretium a, enim. \
    // Pellentesque congue. Ut in risus volutpat libero pharetra tempor. Cras vestibulum \
    // bibendum augue. Praesent egestas leo in pede. Praesent blandit odio eu enim. \
    // Pellentesque sed dui ut augue blandit sodales. Vestibulum ante ipsum primis in \
    // faucibus orci luctus et ultrices posuere cubilia Curae; Aliquam nibh. Morbi vel \
    // justo vitae lacus tincidunt ultrices.";

    // let input = *b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let input = *b"Hello, World!";

    /* #region keys, ivs, and inputs */

    // let state = [
    //     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
    //     0x34,
    // ];

    // let mut cypher_key: [u8; 16] = [
    //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
    //     0x3c,
    // ];

    // let key_temp: [u8; 16] = [
    //     0x8b, 0xed, 0x78, 0xe0, 0xd7, 0x1d, 0x99, 0xf2, 0xb3, 0x44, 0xae, 0x7d, 0xdf, 0x39, 0xb6,
    //     0x91,
    // ];

    // let iv_temp: [u8; 16] = [
    //     0xaa, 0xd2, 0x52, 0x4, 0x14, 0x96, 0x96, 0xa1, 0x8c, 0x94, 0xf9, 0xe9, 0xc4, 0x95, 0xdc,
    //      0x32
    // ];

    let key_temp: [u8; 16] = "habdhufgbtropfhg".as_bytes().try_into().unwrap();
    let iv_temp: [u8; 16] = "ikjzbthfgtreolkf".as_bytes().try_into().unwrap();


    let priv_key_hex = "1155698e40771f86cc03f2c7af0c663bffc5c1cb9e8448ab4887a8ed1501e3978443c95d3c86038152900bb36039779f6fd\
                                62e31c588b9f79174fbe8b9e28f06380b2e0318a153050905c6be00133fc3bd5207bf7e621c7ef6c8c0460bb16ec07c4e\
                                aa8442b73c36ab86c89b4de14c11a9ebaf83c996fc28624c59f8702cf964ba942f9d9d2609d331f7cf13b525715397d97\
                                3800f731c679d46d5eac619f8cd3c549ccd19d551c7d7486c447114948f7a92298c677105a122935f5be15122b67373e9\
                                d2dadce1448054dfb72fa8e85041af1e0bc2ac984b9b8d9b4ae3aa6eaf11701afa8c6bb348ee2cb30142fb4a9f88c9857\
                                3ed52ebc685e5a25ca295161";
    let pub_key_n_hex = "7cfbc938948e6e35a1aa24e9222c17013bd6158c2d6fd74309ef834f78785c59b0bc932a1b7737ff96f4c850d190aed81a\
                                6db83515233b2c8b44ce7f49d06d1382f98b3d1ace0b607ef6e1028a15ccd2f04a5b694c0a0d32b274eb9fae365a97939\
                                2b2e7214429d844b9a2d1549f1eb4b774e2a6aa328e711526ab5630f5a6d1194481cf478206e2d45196662dda389e9d38\
                                42ad3d8fc7fff63c43dcce2566d72717ec1debf33788a4968d9cd88512c79b5a3cf90ce402552922b7fad8ed8242b864a\
                                0bd7b1a0db68151c4f58d86075146aa516fc287165a1582efc0806e2c0b95a56791718250356572fcc6839e28df745b3a\
                                79991055eaf22496704546065";
    let pub_key_e_hex = "10001";

    let priv_key = BigUint::parse_bytes(priv_key_hex.as_bytes(), 16).unwrap();
    let pub_key_n = BigUint::parse_bytes(pub_key_n_hex.as_bytes(), 16).unwrap();
    let pub_key_e = BigUint::parse_bytes(pub_key_e_hex.as_bytes(), 16).unwrap();

    let mut client = RsaClient::from(priv_key, pub_key_n, pub_key_e);

    // print all in hex
    println!("d: {}", &client.private_key.to_str_radix(10));
    println!("n: {}", &client.public_key.0.to_str_radix(10));
    println!("e: {}", &client.public_key.1.to_str_radix(10));

    let state = BigUint::from_bytes_be(&input);

    println!("state: {}\n", hex_as_utf8(&state.to_bytes_be()));

    let mut encrypted = client.encrypt(&state);

    println!("encrypted: {}\n", biguint_to_base64(&encrypted));

    let decrypted = client.decrypt(&encrypted);

    println!("decrypted: {}\n", decrypted.to_str_radix(16));
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

fn biguint_to_base64(bigint: &BigUint) -> String {
    // Convert BigUint to bytes
    let bytes = bigint.to_bytes_le();

    // Encode bytes to Base64
    let base64_string = base64::encode(&bytes);

    base64_string
}

fn insertion_sort(to_sort: &mut Vec<i64>) {
    for i in 1..to_sort.len() {
        let insert = to_sort[i];
        let mut j: i32 = i as i32 - 1;

        while j >= 0 && to_sort[j as usize] > insert {
            to_sort[j as usize + 1] = to_sort[j as usize];
            j -= 1;
        }

        to_sort[(j + 1) as usize] = insert;
    }
}

fn binary_search(vec: &Vec<i64>, search: i64) -> i64 {
    let mut start = 0usize;
    let mut end = vec.len() - 1;

    while start < end {
        let middle: usize = (start + end) as usize / 2;

        if (vec[middle] == search) {
            return middle as i64;
        };

        if (vec[middle] > search) {
            end = middle - 1;
        } else {
            start = middle + 1;
        }
    }

    -1
}
