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
extern crate config;
extern crate keyring;
#[macro_use]
extern crate lazy_static;
extern crate ring;
extern crate rpassword;
#[macro_use]
extern crate serde_derive;
extern crate time;

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

use ring::{digest, pbkdf2};

lazy_static! {
    static ref DEF_CONFIG_PATH: String = {
        let home = std::env::var("HOME").expect("No home directory?");
        format!("{}/.config/pw.toml", home)
    };
}

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

fn get_special(bytes: [u8; digest::SHA256_OUTPUT_LEN], length: u32, special: String) -> char {

    /* we reserve the byte after length */
    let offset = get_next_byte(bytes, length) as usize % special.len();
    return special.chars().nth(offset).unwrap();
}

fn get_reset_offset(period: Option<u32>, date: Option<&str>) -> Result<u32, time::ParseError> {
    let days = date.map_or(Ok(time::now()), |d| time::strptime(d, "%Y-%m-%d"))
        .map(|d| d.to_timespec().sec / (24 * 60 * 60));
    return days.map(|ds| period.map_or(0, |p| ds as u32 / p));
}

enum KeyringKind {
    Password,
}

impl KeyringKind {
    fn as_str<'a>(&self) -> &'a str {
        match self {
            &KeyringKind::Password => "pw",
        }
    }
}

struct KeyringObject<'a> {
    k: keyring::Keyring<'a>,
}

impl<'a> KeyringObject<'a> {
    fn new(t: KeyringKind, user: &'a str) -> Self {
        // if only we had refinement types!
        KeyringObject { k: keyring::Keyring::new(t.as_str(), user) }
    }

    fn get(&self) -> keyring::Result<String> {
        self.k.get_password()
    }

    fn set(&self, data: &str) -> keyring::Result<()> {
        self.k.set_password(data)
    }

    fn delete(&self) -> keyring::Result<()> {
        self.k.delete_password()
    }
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

#[derive(Clone, Default, Debug, Deserialize)]
struct Domain {
    length: Option<u32>,
    special: Option<String>,
    otp: Option<u32>,
    period: Option<u32>,
    user: Option<String>,
    // some optional base64 encoded pre-shared key materieal to add to the user supplied key.
    preshared: Option<String>,
}

fn get_config(file: &str, entity: String) -> Result<Domain, config::ConfigError> {
    let mut c = config::Config::new();
    let err = c.merge(config::File::with_name(file)).err();
    match err {
        Some(e @ config::ConfigError::Foreign(_)) => {
            if file != DEF_CONFIG_PATH.as_str() {
                eprintln!("{} {}", file, DEF_CONFIG_PATH.as_str());
                return Err(e);
            }
            return Ok(Default::default());
        }
        Some(e) => return Err(e),
        None => (),
    }
    let map = c.deserialize::<HashMap<String, Domain>>();
    map.map(|m| {
        m.get(&entity).map(|d| d.clone()).unwrap_or(
            Default::default(),
        )
    })
}

fn main() {
    let matches = clap_app!(pw =>
        (version: "1.0")
        (author: "Tycho Andersen <tycho@tycho.ws>")
        (about: "generates passwords")
        (@arg ENTITY: +required conflicts_with[set_password get_password delete_password]
            "The entity to generate the password for")
        (@arg length: -l --length +takes_value
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
        (@arg get_password: --("get-keyring-password")
            "Gets the keyring password used by pw")
        (@arg delete_password: --("delete-keyring-password")
            "Clears the keyring password")
        (@arg config: -f --("config-file") default_value(DEF_CONFIG_PATH.as_str())
            "The config file to use")
        (@arg question: --question +takes_value
            "An optional security question for the domain")
    ).get_matches();

    let cur_user = std::env::var("USER").expect("couldn't get current user");
    let user = matches.value_of("user").unwrap_or(cur_user.as_str());
    let pass_ring = KeyringObject::new(KeyringKind::Password, user);
    if matches.is_present("delete_password") {
        pass_ring.delete().expect(
            "couldn't delete keyring password",
        );
        return;
    }

    if matches.is_present("set_password") {
        let pass = rpassword::prompt_password_stdout("Password: ").expect("couldn't get password");
        pass_ring.set(pass.as_str()).expect(
            "couldn't set keyring password",
        );
        return;
    }

    let prompt = if matches.is_present("quiet") {
        ""
    } else {
        "Password: "
    };
    let mut pass = pass_ring
        .get()
        .or_else(|_| rpassword::prompt_password_stdout(prompt))
        .expect("couldn't get password");

    if matches.is_present("get_password") {
        println!("{}", pass);
        if matches.is_present("clipboard") && !copy_to_clipboard(pass.as_str()) {
            eprintln!("Problem setting X clipboard");
            std::process::exit(1);
        }
        return;
    }

    let mut entity = matches.value_of("ENTITY").unwrap().to_string();
    matches.value_of("question").map(|q| entity.push_str(q));
    let config_file = matches.value_of("config").unwrap();
    let config = get_config(config_file, entity.to_string()).unwrap_or_else(|e| {
        eprintln!("bad config: {}", e);
        std::process::exit(1)
    });

    config.preshared.map(|p| pass.push_str(p.as_str()));

    let length = value_t!(matches.value_of("length"), u32).unwrap_or(config.length.unwrap_or(10));
    let otp = value_t!(matches.value_of("otp"), u32).unwrap_or(config.otp.unwrap_or(0));
    let period = value_t!(matches.value_of("period"), u32).ok().or(
        config.period,
    );
    let date = matches.value_of("date");
    let offset = get_reset_offset(period, date).unwrap_or_else(|e| {
        eprintln!("bad date: {}", e);
        std::process::exit(1)
    });

    /*
     * 10,000 iterations recommended by NIST, plus 10 iterations for each otp
     * offset, and 10 for the reset offset
     */
    let iterations = 10 * 1000 + otp * 10 + offset * 10;
    let mut raw: [u8; digest::SHA256_OUTPUT_LEN] = [0u8; digest::SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        &digest::SHA256,
        iterations,
        entity.as_bytes(),
        pass.as_bytes(),
        &mut raw,
    );

    let mut result = generate(raw, length);

    let special = if matches.is_present("special") {
        let sps = matches.value_of("special").unwrap_or(
            "!#$%()*+,-.:;=?@[\\]^_{|}~",
        );
        Some(sps.to_string())
    } else {
        config.special
    };

    special.map(|sps| {
        result = result.get(1..).unwrap().to_string();
        result.push_str(&get_special(raw, length, sps).to_string())
    });

    println!("{}", result);

    if matches.is_present("clipboard") && !copy_to_clipboard(result.as_str()) {
        eprintln!("Problem setting X clipboard");
        std::process::exit(1)
    }
}
