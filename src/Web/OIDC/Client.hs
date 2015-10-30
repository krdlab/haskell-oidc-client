{-|
    Module: Web.OIDC.Client
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client
    (
    -- * OpenID Connect Discovery
      module Web.OIDC.Client.Discovery

    -- * Settings and Tokens
    , OIDC, newOIDC, setProvider, setCredentials
    , module Web.OIDC.Client.Tokens

    -- * Authorization Code Flow
    , module Web.OIDC.Client.CodeFlow

    -- * Types and Exceptions
    , module Web.OIDC.Client.Types

    -- * Re-exports
    , module Jose.Jwt
    ) where

import Web.OIDC.Client.CodeFlow
import Web.OIDC.Client.Settings (OIDC, newOIDC, setProvider, setCredentials)
import Web.OIDC.Client.Discovery
import Web.OIDC.Client.Tokens
import Web.OIDC.Client.Types

import Jose.Jwt

{-# ANN module "HLint: ignore Use import/export shortcut" #-}
