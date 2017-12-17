# pw [![Build Status](https://api.travis-ci.org/tych0/pw.svg?branch=master)](https://travis-ci.org/tych0/pw)

`pw` generates passwords statelessly, much like a brain wallet. `pw` has
options to insert special characters, to be used in a One Time Pad mode, to
generate passwords based on the current date (for organizations which require
you to reset your passwords every N days), or to use some pre-shared key
material in addition to the user secret to generate passwords. These options
are all available via the command line, or additionally via a config file,
which can be encrypted via the native OS keyring.

## Installation

To install pw using a [recent](https://www.rustup.rs/) version of rust/cargo, do:

    cargo install pw

It has a few other dependencies, which are likely installed on desktop systems:

* `dbus` on Linux (`libdbus-1-dev` on Ubuntu)
* `gmp` (`libgmp-dev` on Ubuntu)

## Analysis

`pw` uses `pbkdf2` with `sha512` to stretch your password, with the supplied
entity as the salt. The result is encoded in base58, meaning that each symbol
in the password has ~5.86 of entropy. By default, pw generates passwords of
length 20, so there are ~117 bits of entropy per (default) password. By
comparison, ["correct horse battery staple"](https://xkcd.com/936/) is only 44.

#### Password Rotation

Changing passwords, memorably. `pw` offers several features for changing the
generated password for a given salt and user secret combination. For example,
some organizations require users to change their password every 90 days. This
is security theater, but nonetheless, users must cooperate. Using a standard
password generator, users could append a "2" and a "3" ("4"...) to their
password ad infinitum; the problem with this is that it makes some part of the
plaintext input known. `pw` uses a novel method of changing the number of
iterations for `pbkdf2` based on such inputs. `--otp` can be directly used to
change the number of iterations and thus the generated password. `--period` and
`--date` can be used together to work around organizations who e.g. require you
to change your password every 90 days. `--period` alone calculates the password
based on the current date, while `--date` allows you to pass an arbitrary date
for which to calculate password.

#### Adding Special Characters

By default the base58 encoding includes only alphanumeric characters. Some
organizations require special characters in their passwords. Users can add
arbitrary special characters by supplying an argument to `--special`. By
default, `--special` includes 25 typically allowed special characters.

#### Salt Recommendations

The salt is of particular importance to generated passwords. A typical
suggestion is to use the domain of the entity that the password is for, but the
problem is that an attacker who steals usbank.com's password database may just
generate a rainbow table for usbank.com. So, some personalized version of the
salt is recommended. For example, I might choose tycho.usbank.com. An
additional feature (discussed in TODO) would be a global offset for the
algorithm, so people could choose e.g. to not use the default offset of 0, but
something else for all of their passwords.

## Usage

`pw` has support for storing a password in the OS native keyring, via
`--{get,set,delete}-keyring-password`, so that users don't have to type in
their password each invocation.

There is also X11 clipboard support on Linux via `xclip`, so users can pass
`--clipboard` to pw, and it will automatically copy the generated password to
the clipboard.

Finally, worth noting is that `pw` has support for a configuration file,
allowing for a few other features, which can be configured via
`--{get,set,edit,delete}-keyring-config`. For example, users can store OTP
offsets, special character sets, or even pre-shared key material (config key
`preshared`, a string) to use for generating particular passwords. Currently
this config file must be stored in the keyring, so it is not exposed to
unencrypted access. Of course, this is not stateless, and pw can function
entirely without this configuration, but it may be useful to some.

## TODO

* Encrypt the config file. This is mostly supported if you put the config file
  in your keyring, so not a high priority, especially given that I've not seen
  a file encryption library for rust that really jumps out at me.
* global setting for `--otp` to further thwart rainbow tables
