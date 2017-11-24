/*
 * Copyright 2017, Tycho Andersen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate base64;
#[macro_use]
extern crate clap;
extern crate keyring;
extern crate ring;
extern crate rpassword;
extern crate time;

use std::io::Write;
use std::process::{Command, Stdio};

use ring::{digest, pbkdf2};

fn generate(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32) -> String {
    return base64::encode(&bytes)
        .chars()
        .take(length as usize)
        .collect::<String>();
}

fn get_next_byte(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32) -> u8 {
    /* Since we base64 encode stuff, we skip 6 bits (2**6 == 64) per length */
    return bytes[((length as usize * 6) / 8) + 1];
}

fn get_special(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32, special: &str) -> char {

    /* we reserve the byte after length */
    let offset = get_next_byte(bytes, length) as usize % special.len();
    return special.chars().nth(offset).unwrap();
}

fn get_reset_offset(period: Option<u32>, date: Option<&str>) -> Result<u32, time::ParseError> {
    let days = date.map_or(Ok(time::now()), |d| time::strptime(d, "%Y-%m-%d"))
        .map(|d| d.to_timespec().sec / (24 * 60 * 60));
    return days.map(|ds| period.map_or(0, |p| ds as u32 / p));
}

fn get_password(prompt: &str, user: &str) -> std::io::Result<String> {
    let keyring = keyring::Keyring::new("pw", user);
    keyring.get_password().or_else(|_| {
        rpassword::prompt_password_stdout(prompt)
    })
}

fn set_password(user: &str) -> std::result::Result<(), String> {
    let keyring = keyring::Keyring::new("pw", user);
    let pass = rpassword::prompt_password_stdout("Password: ");
    pass.map_err(|e| e.to_string()).and_then(|p| {
        let result = keyring.set_password(p.as_str());
        result.map_err(|e| e.to_string())
    })
}

fn delete_password(user: &str) -> keyring::Result<()> {
    let keyring = keyring::Keyring::new("pw", user);
    keyring.delete_password()
}

fn copy_to_clipboard(data: &str) -> bool {
    /*
     * Note: we use xclip here, instead of some implementation using xlib directly, because the
     * clipboard only lives for the length of time of the process. xclip has code to manage
     * this, forking a child and then owning the clipboard until something else takes over it.
     * We could use xlib directly, but that would force us to either develop this ownership
     * code or have users all run a clipboard manager. For now, let's just use xclip.
     */

    let mut xclip = Command::new("xclip")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("xclip missing");
    xclip
        .stdin
        .as_mut()
        .unwrap()
        .write_all(data.as_bytes())
        .expect("failed writing password to xclip");
    !xclip.wait().map(|e| e.success()).unwrap_or(true)
}

fn main() {
    let matches = clap_app!(pw =>
        (version: "1.0")
        (author: "Tycho Andersen <tycho@tycho.ws>")
        (about: "generates passwords")
        (@arg ENTITY: conflicts_with[set_password delete_password]
            "The entity to generate the password for")
        (@arg length: -l --length +takes_value default_value("10")
            "The length of the password to be generated")
        (@arg special: -s --special +takes_value min_values(0)
            "Special characters to use, if any")
        (@arg otp: -o --otp +takes_value
            "The OTP offset to use")
        (@arg period: -r --reset +takes_value
            "Reset period (in days)")
        (@arg date: -d --date +takes_value requires("period")
            "Date to compute the reset period from (2017-11-22 format)")
        (@arg quiet: -q --quiet
            "Whether or not to prompt when getting the password from stdin")
        (@arg clipboard: -c --clipboard
            "Copy the password to the clipboard")
        (@arg user: -u --user
            "User to query the keyring for, if not the current user.")
        (@arg set_password: --("set-keyring-password")
            "Sets the keyring password for use by pw")
        (@arg delete_password: --("delete-keyring-password")
            "Clears the keyring password")
    ).get_matches();

    let cur_user = std::env::var("USER").expect("couldn't get current user");
    let user = matches.value_of("user").unwrap_or(cur_user.as_str());
    if matches.is_present("delete_password") {
        delete_password(user).expect("couldn't delete keyring password");
        return;
    }

    if matches.is_present("set_password") {
        set_password(user).expect("couldn't set keyring password");
        return;
    }

    let entity = matches.value_of("ENTITY").unwrap().as_bytes();
    let prompt = if matches.is_present("quiet") {
        ""
    } else {
        "Password: "
    };
    let pass = get_password(prompt, user).expect("couldn't get password");
    let mut raw: [u8; digest::SHA256_OUTPUT_LEN] = [0u8; digest::SHA256_OUTPUT_LEN];

    let otp = value_t!(matches.value_of("otp"), u32).unwrap_or(0);
    let reset = value_t!(matches.value_of("period"), u32).ok();
    let date = matches.value_of("date");
    let offset = get_reset_offset(reset, date).unwrap_or_else(|e| {
        eprintln!("bad date: {}", e);
        std::process::exit(1)
    });

    /*
     * 10,000 iterations recommended by NIST, plus 10 iterations for each otp
     * offset, and 10 for the reset offset
     */
    let iterations = 10 * 1000 + otp * 10 + offset * 10;
    pbkdf2::derive(
        &digest::SHA256,
        iterations,
        entity,
        pass.as_bytes(),
        &mut raw,
    );

    let length = value_t_or_exit!(matches.value_of("length"), u32);
    let mut result = generate(raw, length);

    if matches.is_present("special") {
        /*
         * We specify the default value here instead of above, because this way
         * passing -s without any values is allowed
         */
        let special = matches.value_of("special").unwrap_or(
            "!#$%()*+,-.:;=?@[\\]^_{|}~",
        );
        result = result.get(1..).unwrap().to_string();
        result.push_str(&get_special(raw, length, special).to_string());
    }

    println!("{}", result);

    if matches.is_present("clipboard") && !copy_to_clipboard(result.as_str()) {
        eprintln!("Problem setting X clipboard");
        std::process::exit(1)
    }
}
