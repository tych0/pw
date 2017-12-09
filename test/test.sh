#!/bin/bash -e

export RUST_BACKTRACE=1

function pw() {
    echo asdf | cargo run -- -u pw-test-user -q "$@"
}

function cleanup() {
    set +x
    if [ -n "$TRAVIS" ]; then
        return;
    fi
    cargo run -- -u pw-test-user --delete-keyring-password >& /dev/null
    cargo run -- -u pw-test-user --delete-keyring-config >& /dev/null
    rm ./from_keyring.toml >& /dev/null || true
}
trap cleanup EXIT HUP INT TERM

set -x

# test -d with a hand computed password
[ "$(pw -r 180 zomg -d 2017-11-22)" = "EQxydrykDveWY84ZsWov" ]

# test -r doesn't change too early
for i in $(seq 1 10); do
    [ "$(pw -r 10 zomg -d 2010-01-$i)" = "FYcayYm291XQtDBEkLKB" ]
done
[ "$(pw -r 10 zomg -d 2010-01-11)" = "7Z1iqJB7Xz4TBqM4GkpS" ]

# test changing -r changes things
[ "$(pw -r 10 zomg)" != "$(pw -r 20 zomg)" ]

# test -o
[ "$(pw zomg)" = "giDbm2guRMRq3Koybh4B" ]
[ "$(pw -o 0 zomg)" = "giDbm2guRMRq3Koybh4B" ]
[ "$(pw -o 1 zomg)" = "2MDrfpXVhUq3JJRtgjEt" ]
[ "$(pw -o 2 zomg)" = "y3dkwr7ahiJXifqVxhyy" ]

# test -s
[ "$(pw zomg -s)" = "g[Dbm2guRMRq3Koybh4B" ]

# test -l
[ "$(pw -l 30 zomg)" = "giDbm2guRMRq3Koybh4BM4MjwsM7hY" ]

# test -l -s
[ "$(pw zomg -l 30 -s)" = "giDbm]guRMRq3Koybh4BM4MjwsM7hY" ]

# test otp config fallback
[ "$(pw -f ./test.toml zomg)" = "2MDrfpXVhUq3JJRtgjEt" ]
[ "$(pw -f ./test.toml zomg -o 2)" = "y3dkwr7ahiJXifqVxhyy" ]
[ "$(pw -f ./test.toml this.has.dots.com -o 2)" = "MoAGM265AfzuT5EyoVJZ" ]

# test --question
[ "$(pw zomg --question "Do you like trees?")" = "2AiVuhbkDC43FqtkNwXi" ]

# test preshared config option
[ "$(pw zomg -f ./preshared.toml)" = "Z8MhYSqsZzZXAy1DYJiM" ]


# Below here we can't test on travis, because it doesn't have secretservice.
if [ -n "$TRAVIS" ]; then
    exit 0
fi

echo -e "asdf\nasdf" | cargo run -- -q -u pw-test-user --set-keyring-password
[ "$(pw --get-keyring-password)" == "asdf" ]

# explicitly use cargo run, so we can be sure to bypass entering the password
[ "$(cargo run -- -u pw-test-user zomg)" = "giDbm2guRMRq3Koybh4B" ]

# test that we don't mutliate the config
pw --set-keyring-config ./keyring.toml
pw --get-keyring-config ./from_keyring.toml
[ "$(sha256sum ./keyring.toml | cut -f1 -d" ")" == "$(sha256sum ./from_keyring.toml | cut -f1 -d" ")" ]
rm ./from_keyring.toml

# now test that we got the right otp=1 password from the keyring config
[ "$(pw zomg)" = "2MDrfpXVhUq3JJRtgjEt" ]
