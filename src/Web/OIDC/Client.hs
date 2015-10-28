{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GADTs #-}
{-|
Module: Web.OIDC.Client
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client
    (
    -- * Obtaining OpenID Provider Configuration Information
      discover

    -- * Obtaining ID Token and Access Token
    , OIDC
    , newOIDC
    , newOIDC'
    , setProvider
    , setCredentials

    -- * Authorization Code Flow
    , module Web.OIDC.Client.CodeFlow

    -- * Types
    , Provider
    , Scope, ScopeValue(..)
    , Code, State
    , Parameters
    , Tokens(..), IdToken(..), IdTokenClaims(..)

    -- * Exception
    , OpenIdException(..)

    -- * Re-exports
    , module Jose.Jwt
    ) where

import Web.OIDC.Client.CodeFlow
import Web.OIDC.Client.Context
import Web.OIDC.Client.Discovery
import Web.OIDC.Client.Discovery.Provider
import Web.OIDC.Client.Tokens
import Web.OIDC.Client.Types

import Jose.Jwt
