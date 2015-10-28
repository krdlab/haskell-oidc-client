{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Tokens
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Tokens
    (
      Tokens(..)
    , IdToken(..)
    , IdTokenClaims(..)
    ) where

import Jose.Jwt (Jwt, IntDate)
import Prelude hiding (exp)

data Tokens = Tokens
    { accessToken :: String
    , tokenType :: String
    , idToken :: IdToken
    , expiresIn :: Maybe Integer
    , refreshToken :: Maybe String
    }
  deriving (Show, Eq)

data IdToken = IdToken
    { claims :: IdTokenClaims
    , jwt :: Jwt
    }
  deriving (Show, Eq)

data IdTokenClaims = IdTokenClaims
    { iss :: String
    , sub :: String
    , aud :: [String]
    , exp :: IntDate
    , iat :: IntDate
    -- TODO: optional
    }
  deriving (Show, Eq)
