extern crate base64;
#[macro_use]
extern crate clap;
extern crate ring;
extern crate rpassword;

use ring::{digest, pbkdf2};

fn generate(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32) -> String {
    return base64::encode(&bytes).chars().take(length as usize).collect::<String>();
}

fn main() {
    let matches = clap_app!(pw =>
        (version: "1.0")
        (author: "Tycho Andersen <tycho@tycho.ws>")
        (about: "generates passwords")
        (@arg ENTITY: +required "The entity to generate the password for")
        (@arg length: -l --length +takes_value default_value("10")
            "The length of the password to be generated")
    ).get_matches();

    let entity = matches.value_of("ENTITY").unwrap().as_bytes();
    let pass = rpassword::prompt_password_stdout("Password: ").unwrap();
    let mut raw: [u8; digest::SHA256_OUTPUT_LEN] = [0u8; digest::SHA256_OUTPUT_LEN];

    pbkdf2::derive(&digest::SHA256, 10000, entity, pass.as_bytes(), &mut raw);

    let length = value_t!(matches.value_of("length"), u32).unwrap();

    println!("{}", generate(raw, length));
}
