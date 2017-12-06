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
[ "$(pw -r 180 zomg -d 2017-11-22)" = "56FAdSQuVAJEKbZmjJ3E" ]

# test -r doesn't change too early
for i in $(seq 1 10); do
    [ "$(pw -r 10 zomg -d 2010-01-$i)" = "2kKQp5YZhBNqNB6Vfvfv" ]
done
[ "$(pw -r 10 zomg -d 2010-01-11)" = "33zajgdUXdYdxM1Vf8Uw" ]

# test changing -r changes things
[ "$(pw -r 10 zomg)" != "$(pw -r 20 zomg)" ]

# test -o
[ "$(pw zomg)" = "35iLqmvYkvn1XiHx79p8" ]
[ "$(pw -o 0 zomg)" = "35iLqmvYkvn1XiHx79p8" ]
[ "$(pw -o 1 zomg)" = "u8iiCCb3jxUuneoUZz74" ]
[ "$(pw -o 2 zomg)" = "5tkUZg7jmr6WpmG73oa5" ]

# test -s
[ "$(pw zomg -s)" = "3[iLqmvYkvn1XiHx79p8" ]

# test -l
[ "$(pw -l 30 zomg)" = "35iLqmvYkvn1XiHx79p8XohdTEvDTQ" ]

# test -l -s
[ "$(pw zomg -l 30 -s)" = "35iLq]vYkvn1XiHx79p8XohdTEvDTQ" ]

# test otp config fallback
[ "$(pw -f ./test.toml zomg)" = "u8iiCCb3jxUuneoUZz74" ]
[ "$(pw -f ./test.toml zomg -o 2)" = "5tkUZg7jmr6WpmG73oa5" ]

# test --question
[ "$(pw zomg --question "Do you like trees?")" = "4ikXexSJLsWYd3Wu1DYy" ]

# test preshared config option
[ "$(pw zomg -f ./preshared.toml)" = "4TGjqSEHv1ve9KXJunnb" ]


# Below here we can't test on travis, because it doesn't have secretservice.
if [ -n "$TRAVIS" ]; then
    exit 0
fi

echo -e "asdf\nasdf" | cargo run -- -q -u pw-test-user --set-keyring-password
[ "$(pw --get-keyring-password)" == "asdf" ]

# explicitly use cargo run, so we can be sure to bypass entering the password
[ "$(cargo run -- -u pw-test-user zomg)" = "35iLqmvYkvn1XiHx79p8" ]

# test that we don't mutliate the config
pw --set-keyring-config ./keyring.toml
pw --get-keyring-config ./from_keyring.toml
[ "$(sha256sum ./keyring.toml | cut -f1 -d" ")" == "$(sha256sum ./from_keyring.toml | cut -f1 -d" ")" ]
rm ./from_keyring.toml

# now test that we got the right otp=1 password from the keyring config
[ "$(pw zomg)" = "u8iiCCb3jxUuneoUZz74" ]
