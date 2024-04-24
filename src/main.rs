use std::env::Args;

use crate::aes::{print_hex, AES128};
mod aes;
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


enum Mode {
    FileEncryption,
    TextEncryption,
    FileDecryption,
    TextDecryption,
    None,
}

struct Parser {
    args: Args,
    mode: Mode,
}

impl Parser {
    fn new(args: Args) -> Parser {
        Parser {
            args: args,
            mode: Mode::None,
        }
    }

    fn run(&mut self) {
        // Parse the command line arguments
        self.parse_mode();

        // Perform the appropriate action based on the mode
        match self.mode {
            Mode::FileEncryption => self.file_encrypt(),
            Mode::TextEncryption => self.text_encrypt(),
            Mode::FileDecryption => self.file_decrypt(),
            Mode::TextDecryption => self.text_decrypt(),
            Mode::None => panic!("{}", Self::usage_string_error("No mode was provided!")),
        }
    }

    fn usage_string_error(error: &str) -> String {
        format!(
            "{}
            USAGE: aes128 [MODE] [args...]

            MODE:
                fe - File encrypt
                te - Text encrypt
                fd - File decrypt
                td - Text decrypt

            args:
                -i=FILE, input file
                -o=FILE, output file
                -t=TEXT, text to en-, decrypt",
            error
        )
    }

    fn parse_mode(&mut self) {
        let error = Self::usage_string_error("Noe moed was Provided");

        let mode = self
            .args
            .nth(1)
            .expect(Self::usage_string_error(&error.as_str()).as_str());
        let mode_str = mode.as_str();
        self.mode = match mode_str {
            "fe" => Mode::FileEncryption,
            "fd" => Mode::FileDecryption,
            "te" => Mode::TextEncryption,
            "td" => Mode::TextDecryption,

            _ => panic!(
                "{}",
                Self::usage_string_error(format!("Mode {} is not a valid mode", mode).as_str())
            ),
        };
    }

    fn file_encrypt(&self) {
        // Implement file encryption logic here
    }

    fn text_encrypt(&self) {
        // Implement text encryption logic here
    }

    fn file_decrypt(&self) {
        // Implement file decryption logic here
    }

    fn text_decrypt(&self) {
        // Implement text decryption logic here
    }
}

fn main() {
    let input = "A block cipher works on units of a fixed size \
    (known as a block size), but messages come in a variety of lengths. \
    So some modes (namely ECB and CBC) require that the final block be padded before encryption. \
    Several padding schemes exist. The simplest is to add null bytes to the plaintext to bring its \
    length up to a multiple of the block size, but care must be taken that the original length of \
    the plaintext can be recovered; this is trivial, for example, if the plaintext is a C style string which \
    contains no null bytes except at the end. Slightly more complex is the original DES method, which is to add a single one bit, \
    followed by enough zero bits to fill out the block; if the message ends on a block boundary, \
    a whole padding block will be added. Most sophisticated are CBC-specific schemes such as ciphertext stealing \
    or residual block termination, which do not cause any extra ciphertext, at the expense of some additional complexity. \
    Schneier and Ferguson suggest two possibilities, both simple: append a byte with value 128 (hex 80), followed \
    by as many zero bytes as needed to fill the last block, or pad the last block with n bytes all with value n. ";
    let state = input.as_bytes().to_vec();
    // let state = [
    //     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
    //     0x34,
    // ];

    let mut cypher_key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    let mut aes = AES128::new();
    

    aes.generate_key();

    let cypher = aes.encrypt_ecb(&state);

    print_hex(&cypher);

    let plain_text = aes.decrypt_ecb(&cypher);
    println!("Decrypted text: ");

    print_hex(&plain_text);

    // in ascii
    let plain_text = String::from_utf8(plain_text).unwrap();
    println!("{}", plain_text);
}
