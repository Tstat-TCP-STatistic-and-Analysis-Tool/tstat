# QUIC regressions

On Ubuntu, install the dependencies listed in the main README, then run:

```sh
make test
```

The C test includes `udpL7.c` to exercise its static functions. Linker garbage
collection excludes unrelated plugins; no production API is added for testing.
Cases cover RFC 9000 varints, truncation at each field boundary, a token longer
than 255 bytes, and coalesced packet offsets and classification.

For address and undefined-behavior checks (requires Clang):

```sh
UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=detect_leaks=1 \
make -B test CC=clang \
  CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined'
```

Use `-B` when changing flags so the test executable is rebuilt.
