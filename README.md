# pw

`pw` generates passswords statelessly, much like a brain wallet. `pw` also has
several options to encode passwords to satisfy several common password
requirements.

## Crypto

`pw` uses `pbkdf2` with `sha256` to stretch your password, with the supplied
entity as the salt. It then base64 encodes the resulting stretched bytes, and
grabs the first N (default 10) characters of that as a password. Since each
character in base64 represents 2<sup>6</sup> of entropy (hence the 64), a
password of length 10 is roughly 60 bits of entropy. By comparison, ["correct
horse battery staple"](https://xkcd.com/936/) is only 44.

## TODO

* ensure there is a special character
* option to generate a password based on a reset period
* option to generate the nth password, like an OTP
* config file to store reset period/nth password/special character state
* keyring support for actual password
* copy stuff to the X clipboard on request
