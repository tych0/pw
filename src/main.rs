extern crate base64;
#[macro_use]
extern crate clap;
extern crate ring;
extern crate rpassword;

use ring::{digest, pbkdf2};

fn generate(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32) -> String {
    return base64::encode(&bytes).chars().take(length as usize).collect::<String>();
}

fn get_next_byte(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32) -> u8 {
    /* Since we base64 encode stuff, we skip 6 bits (2**6 == 64) per length */
    return bytes[((length as usize * 6) / 8) + 1]
}

fn get_special(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32,
               special: &str) -> char {

    /* we reserve the byte after length */
    let offset = get_next_byte(bytes, length) as usize % special.len();
    return special.chars().nth(offset).unwrap()
}

fn main() {
    let matches = clap_app!(pw =>
        (version: "1.0")
        (author: "Tycho Andersen <tycho@tycho.ws>")
        (about: "generates passwords")
        (@arg ENTITY: +required "The entity to generate the password for")
        (@arg length: -l --length +takes_value default_value("10")
            "The length of the password to be generated")
        (@arg special: -s --special +takes_value min_values(0)
            "Special characters to use, if any")
    ).get_matches();

    let entity = matches.value_of("ENTITY").unwrap().as_bytes();
    let pass = rpassword::prompt_password_stdout("Password: ").unwrap();
    let mut raw: [u8; digest::SHA256_OUTPUT_LEN] = [0u8; digest::SHA256_OUTPUT_LEN];

    pbkdf2::derive(&digest::SHA256, 10000, entity, pass.as_bytes(), &mut raw);

    let length = value_t!(matches.value_of("length"), u32).unwrap();

    let mut result = generate(raw, length);

    if matches.is_present("special") {
        /*
         * We specify the default value here instead of above, because this way
         * passing -s without any values is allowed
         */
        let special = matches.value_of("special").unwrap_or("!#$%()*+,-.:;=?@[\\]^_{|}~");
        result = result.get(1..).unwrap().to_string();
        result.push_str(&get_special(raw, length, special).to_string());
    }

    println!("{}", result);
}
