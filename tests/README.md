# QUIC regressions

On Ubuntu, install the dependencies listed in the main README, then run:

```sh
make test
```

The C test includes `udpL7.c` to exercise its static functions. Linker garbage
collection excludes unrelated plugins; no production API is added for testing.
Cases cover RFC 9000 varints, truncation at each field boundary, a token longer
than 255 bytes, token encoding boundaries at 63/64 and 16383/16384, and
coalesced packet offsets and classification. Version Negotiation and Retry
are not parsed as Initial packets; tests verify that they leave a pending
flow intact and a subsequent server Initial still classifies both directions.
These header-only fixtures deliberately skip Initial key derivation; full
decryption and packet replay are covered by the follow-up PR.

For address and undefined-behavior checks (Clang shown below; GCC also works):

```sh
UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=detect_leaks=1 \
make -B test CC=clang \
  CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined'
```

Use `-B` when changing flags so the test executable is rebuilt.
The same sanitizer command works with GCC: replace `CC=clang` with `CC=gcc`.
