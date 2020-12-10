# Crux.Crypto ![](https://github.com/SpaceEEC/crux_crypto/workflows/Tests/badge.svg?event=push&branch=master)

Crux.Crypto wraps a very small subset of [libsodium](https://github.com/jedisct1/libsodium) using [erl_nif](http://erlang.org/doc/man/erl_nif.html)s.

This subset consists of the functions
- `randombytes_buf`
- `crypto_secretbox_easy`
- `crypto_secretbox_open_easy`
- `crypto_sign_verify_detached`

## Installation

Like usual, add `crux_crypto` to your list of dependencies in your `mix.exs` file:

```elixir
def deps() do
[
    {:crux_crypto, github: "SpaceEEC/crux_crypto"}
]
end
```

### Windows

You need to have the [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) installed.

Then launch a `x64 Native Tools Command Prompt [...]` and install Crux.Crypto using it.

### Everything else

You need to have your regular build tools installed (read: make and a C compiler).
You also need sodium and its headers.
