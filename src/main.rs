mod aes128;
use std::f32::consts::E;

use aes128::AES128;

mod rsa_client;
use base64::Engine;
use image::GenericImageView;
use num::{Float, FromPrimitive, Num};
use num_bigint::BigUint;
use num_bigint::{RandBigInt, RandomBits, ToBigUint};
use pem::parse;
use rand::{thread_rng, Rng};
use rsa_client::{is_prime, RsaClient};

use crate::rsa_client::PrivateKey;
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

    // TODO: read image and encrypt it with ecb and cbc

    // read only data of the image not the whole file using image
    let img = image::open("assets/image.jpg").unwrap();

    println!("Image dimensions: {:?}", img.dimensions());
    let bytes = img.as_bytes().to_vec();

    let aes = AES128::new();


    let encrypted_ecb = aes.encrypt_ecb(&bytes);

    let encrypted_cbc = aes.encrypt_cbc(&bytes);

    
    let cut_off_ecb = encrypted_ecb[0..bytes.len()].to_vec();
    let cut_off_cbc = encrypted_cbc[0..bytes.len()].to_vec();


    // write

    let img_ecb = image::RgbImage::from_vec(img.width(), img.height(), cut_off_ecb).unwrap();
    img_ecb.save("assets/image_ecb.jpg").unwrap();

    let img_cbc = image::RgbImage::from_vec(img.width(), img.height(), cut_off_cbc).unwrap();
    img_cbc.save("assets/image_cbc.jpg").unwrap();


    // raad ecb image
    let img_enc_ecb = image::open("assets/image_ecb.jpg").unwrap();

    let bytes_enc_ecb = img_enc_ecb.as_bytes().to_vec();

    let decrypted_ecb = aes.decrypt_ecb(&bytes_enc_ecb);

    let img_dec_ecb = image::RgbImage::from_vec(img.width(), img.height(), decrypted_ecb).unwrap();

    img_dec_ecb.save("assets/image_dec_ecb.jpg").unwrap();

    
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

fn phi(n: &BigUint) -> BigUint {
    let mut result = BigUint::from_u8(1).unwrap();
    let mut i = BigUint::from_u8(2).unwrap();
    let mut ne: BigUint = n.to_owned();

    while &i < &ne {
        if &ne % &i == BigUint::from_u8(0).unwrap() {
            result = result * (&i - BigUint::from_u8(1).unwrap());
            ne = ne / &i;
        }
        i = &i + BigUint::from_u8(1).unwrap();
    }

    if ne > BigUint::from_u8(1).unwrap() {
        result = result * (n - BigUint::from_u8(1).unwrap());
    }

    result
}
