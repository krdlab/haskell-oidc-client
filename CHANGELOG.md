# ChangeLog

## [0.6.0.0]
### Added
- Preserve the raw JWT in the tokens record returned by `validate` ([#43](https://github.com/krdlab/haskell-oidc-client/pull/43))

### Fixed
- s/JwtExceptoin/JwtException/ ([#45](https://github.com/krdlab/haskell-oidc-client/pull/45))
- import data.monoid ([#46](https://github.com/krdlab/haskell-oidc-client/pull/46))

## [0.5.1.0]
### Fixed
- fix: generate correct discovery url ([#39](https://github.com/krdlab/haskell-oidc-client/pull/39))
- Fix discovery URL generation ([#40](https://github.com/krdlab/haskell-oidc-client/pull/40))
    - Corrected more cases

## [0.5.0.0]
### Added
- Add implicit id_token flow. See [#34](https://github.com/krdlab/haskell-oidc-client/pull/34).

### Changed
- discover: Append well-known part to parsed request. See [#33](https://github.com/krdlab/haskell-oidc-client/pull/33).

### Fixed
- Fix unsupported algorithm error. See [#36](https://github.com/krdlab/haskell-oidc-client/pull/36).

## [0.4.0.1]
### Fixed
- Allow for multiple algorithms in the JWK Set. See [#28](https://github.com/krdlab/haskell-oidc-client/pull/28).
- Support GHC < 8.4. See [#30](https://github.com/krdlab/haskell-oidc-client/issues/30).

## [0.4.0.0]
### Added
- Added a validation of 'nonce' parameter. See [#24](https://github.com/krdlab/haskell-oidc-client/pull/24).
- Made optional claims available. See [#24](https://github.com/krdlab/haskell-oidc-client/pull/24).
- The lifecycles of 'nonce' and 'state' can also be managed by `SessionStore`. See [#24](https://github.com/krdlab/haskell-oidc-client/pull/24).

### Changed
- Made `TokenResponse` parsing strict. See [#23](https://github.com/krdlab/haskell-oidc-client/pull/23).
- A signing algorithm is now obtained from OpenID Provider Metadata. See [#24](https://github.com/krdlab/haskell-oidc-client/pull/24).
- 'profile' scope added to 'examples/scotty', and name / email / picture shown. See [#25](https://github.com/krdlab/haskell-oidc-client/pull/25).

## [0.3.0.1]
### Changed
- 'expires_in' can now parsed both String and Decimal number. See [#15](https://github.com/krdlab/haskell-oidc-client/pull/15).

### Fixed
- Improved error messages. See [#15](https://github.com/krdlab/haskell-oidc-client/pull/15).

## [0.3.0.0]
### Changed
- Changed `Configuration` fileds. See [#11](https://github.com/krdlab/haskell-oidc-client/pull/11).

### Fixed
- Fixed Hackage tarball. See [#13](https://github.com/krdlab/haskell-oidc-client/pull/13).

## [0.2.0.0]
### Changed
- Refactored modules, exports, types, and functions.

## [0.1.0.1]
### Changed
- Adjusted dependency version.

## [0.1.0.0]

First public release.
