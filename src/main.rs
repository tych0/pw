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

extern crate rust_base58;
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
extern crate tempfile;
extern crate time;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use rust_base58::ToBase58;
use config::FileFormat;
use keyring::KeyringError;
use ring::{digest, pbkdf2};

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA512;
const DIGEST_LEN: usize = digest::SHA512_OUTPUT_LEN;
type RandomBuffer = [u8; DIGEST_LEN];

lazy_static! {
    static ref DEF_CONFIG_PATH: String = {
        let home = std::env::var("HOME").expect("No home directory?");
        format!("{}/.config/pw.toml", home)
    };
}

fn generate(bytes: RandomBuffer, length: u32) -> String {
    return bytes[..]
        .to_base58()
        .chars()
        .take(length as usize)
        .collect::<String>();
}

fn get_next_byte(bytes: RandomBuffer, length: u32) -> u8 {
    /* Since we base64 encode stuff, we skip 6 bits (2**6 == 64) per length */
    return bytes[((length as usize * 6) / 8) + 1];
}

fn get_special(bytes: RandomBuffer, length: u32, special: String) -> char {

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
    ConfigFile,
}

impl KeyringKind {
    fn as_str<'a>(&self) -> &'a str {
        match self {
            &KeyringKind::Password => "pw",
            &KeyringKind::ConfigFile => "pw-config",
        }
    }

    fn validate(&self, data: &str) -> Result<(), String> {
        match self {
            &KeyringKind::ConfigFile => {
                let mut c = config::Config::new();
                if let Some(e) = c.merge(config::File::from_str(data, FileFormat::Toml))
                    .err()
                {
                    return Err(e.to_string());
                }
                c.deserialize::<HashMap<String, Domain>>()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            _ => Ok(()),
        }
    }
}

struct KeyringObject<'a> {
    t: KeyringKind,
    user: &'a str,
}

impl<'a> KeyringObject<'a> {
    fn new(t: KeyringKind, user: &'a str) -> Self {
        // if only we had refinement types!
        KeyringObject { t: t, user: user }
    }

    fn get(&self) -> keyring::Result<String> {
        keyring::Keyring::new(self.t.as_str(), self.user).get_password()
    }

    fn set(&self, data: &str) -> Result<(), String> {
        let k = keyring::Keyring::new(self.t.as_str(), self.user);
        self.t.validate(data).and(k.set_password(data).map_err(
            |e| e.to_string(),
        ))
    }

    fn delete(&self) -> keyring::Result<()> {
        let k = keyring::Keyring::new(self.t.as_str(), self.user);
        match k.delete_password() {
            Err(KeyringError::NoPasswordFound) => Ok(()),
            x => x,
        }
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

fn get_config(config_ring: KeyringObject, file: &str, entity: String) -> Result<Domain, String> {
    let mut c = config::Config::new();

    // First, add in the config from the keyring.
    if let Ok(s) = config_ring.get() {
        if file != DEF_CONFIG_PATH.as_str() {
            return Err("both keyring and config file config specified".to_string());
        }
        let source = config::File::from_str(s.as_str(), FileFormat::Toml);
        if let Some(e) = c.merge(source).err() {
            return Err(e.to_string());
        }
    } else if Path::new(file).is_file() {
        let source = config::File::with_name(file);
        if let Some(e) = c.merge(source).err() {
            return Err(e.to_string());
        }
    } else if file == DEF_CONFIG_PATH.as_str() {
        return Ok(Default::default());
    }

    let map = c.deserialize::<HashMap<String, Domain>>();
    map.map_err(|e| e.to_string()).map(|m| {
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
        (@arg ENTITY: +required conflicts_with[set_password get_password
            delete_password set_config edit_config delete_config get_config]
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
        (@arg user: -u --user +takes_value
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
        (@arg set_config: --("set-keyring-config") +takes_value
            "Sets the config in the keyring to the specified file")
        (@arg edit_config: --("edit-keyring-config")
            "Edit the config in the keyring")
        (@arg delete_config: --("delete-keyring-config")
            "Delete the keyring config")
        (@arg get_config: --("get-keyring-config") +takes_value
            "Gets the config from the keyring and writes it to the specified file")
    ).get_matches();

    let cur_user = std::env::var("USER").expect("couldn't get current user");
    let user = matches.value_of("user").unwrap_or(cur_user.as_str());

    let config_ring = KeyringObject::new(KeyringKind::ConfigFile, user);
    if matches.is_present("delete_config") {
        config_ring.delete().expect(
            "couldn't delete keyring config",
        );
        return;
    }

    if let Some(p) = matches.value_of("set_config") {
        let mut content = String::from("");
        File::open(p)
            .expect("couldn't open file")
            .read_to_string(&mut content)
            .expect("couldn't read file");
        config_ring.set(content.as_str()).expect(
            "couldn't set keyring config",
        );
        return;
    }

    if matches.is_present("edit_config") {
        let content = match config_ring.get() {
            Ok(c) => c,
            Err(KeyringError::NoPasswordFound) => String::new(),
            e => e.expect("couldn't get keyring config"),
        };
        let mut f = tempfile::NamedTempFileOptions::new()
            .prefix("pw_config_")
            .rand_bytes(5)
            .create()
            .expect("couldn't create temp file for editing");
        f.as_mut().write_all(content.as_bytes()).expect(
            "couldn't write tempfile",
        );
        let editor = std::env::var("EDITOR").unwrap_or("vi".to_string());
        let edit = Command::new(editor)
            .arg(f.path().as_os_str())
            .status()
            .map(|e| e.success())
            .unwrap_or(false);
        if !edit {
            eprintln!("edit not successful");
            std::process::exit(1)
        }
        f.as_mut().seek(std::io::SeekFrom::Start(0)).expect(
            "couldn't seek in tempfile",
        );
        let mut content = String::from("");
        f.read_to_string(&mut content).expect(
            "couldn't read tempfile",
        );
        config_ring.set(content.as_str()).expect(
            "couldn't set keyring config",
        );
        return;
    }

    if let Some(p) = matches.value_of("get_config") {
        let content = config_ring.get().expect("couldn't get keyring config");
        let mut f = File::create(p).expect("couldn't open file for creation");
        f.write_all(content.as_bytes()).expect(
            "couldn't write file",
        );
        return;
    }

    let pass_ring = KeyringObject::new(KeyringKind::Password, user);
    if matches.is_present("delete_password") {
        pass_ring.delete().expect(
            "couldn't delete keyring password",
        );
        return;
    }

    if matches.is_present("set_password") {
        let pass1 = rpassword::prompt_password_stdout("Password: ").expect("couldn't get password");
        let pass2 = rpassword::prompt_password_stdout("Password: ").expect("couldn't get password");
        if pass1 != pass2 {
            eprintln!("passwords aren't equal!");
            std::process::exit(1);
        }
        pass_ring.set(pass1.as_str()).expect(
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
    let config = get_config(config_ring, config_file, entity.to_string()).unwrap_or_else(|e| {
        eprintln!("bad config: {}", e);
        std::process::exit(1)
    });

    config.preshared.map(|p| pass.push_str(p.as_str()));

    let length = value_t!(matches.value_of("length"), u32).unwrap_or(config.length.unwrap_or(20));
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
    let mut raw: RandomBuffer = [0u8; DIGEST_LEN];
    pbkdf2::derive(
        DIGEST_ALG,
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
        let sp = &get_special(raw, length, sps);
        let mut r_bytes = result.clone().into_bytes();
        let offset = get_next_byte(raw, length+1) as usize % length as usize;
        *r_bytes.get_mut(offset).expect("unreachable") = *sp as u8;
        result = String::from_utf8_lossy(&mut r_bytes).to_string()
    });

    println!("{}", result);

    if matches.is_present("clipboard") && !copy_to_clipboard(result.as_str()) {
        eprintln!("Problem setting X clipboard");
        std::process::exit(1)
    }
}
