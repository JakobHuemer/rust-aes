
mod aes128;
use aes128::AES128;

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

    let input = *b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // let input = *b"Hello world hellawd";

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

    /* #endregion */

    println!("Original: ");
    print_as_hex(&(input.to_vec()));
    println!();

    /* #region own aes */

    let mut aes = AES128::new();

    aes.key = key_temp;
    aes.iv_vector = iv_temp;

    let cypher = aes.encrypt_cbc(&input.to_vec());

    println!("Own AES Encr:");
    print_as_hex(&cypher);
    println!();

    let plain = aes.decrypt_cbc(&cypher);

    println!("Own AES Decr:");
    print_as_hex(&plain);
    println!("'{}'", hex_as_utf8(&plain));
    println!();

    /* #endregion */


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
