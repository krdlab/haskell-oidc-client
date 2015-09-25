# OpenID Connect 1.0 library for Relying Party

[![Circle CI](https://circleci.com/gh/krdlab/haskell-oidc-client.svg?style=svg)](https://circleci.com/gh/krdlab/haskell-oidc-client)

This package supports implementing of an OpenID Connect 1.0 Relying Party. It's written in Haskell.

This package uses [jose-jwt](http://github.com/tekul/jose-jwt) package for decoding a received tokens.

## Usage

To be prepared.

## Run example

`examples/scotty` is a runnable code. If you try to run it, execute commands as follows:

```sh
$ cabal sandbox init
$ cabal install --only-dependencies -fbuild-examples
$ cabal configure -fbuild-examples
$ cabal build
```

and then

```sh
$ export OPENID_CLIENT_ID="Your client ID"
$ export OPENID_CLIENT_SECRET="Your client secret"
$ cabal run scotty-example
```

You can access to <http://localhost:3000/login>.
