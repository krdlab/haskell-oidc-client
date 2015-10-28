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

import Data.Text (Text)
import Jose.Jwt (Jwt, IntDate)
import Prelude hiding (exp)

data Tokens = Tokens
    { accessToken   :: Text
    , tokenType     :: Text
    , idToken       :: IdToken
    , expiresIn     :: Maybe Integer
    , refreshToken  :: Maybe Text
    }
  deriving (Show, Eq)

data IdToken = IdToken
    { claims    :: IdTokenClaims
    , jwt       :: Jwt
    }
  deriving (Show, Eq)

data IdTokenClaims = IdTokenClaims
    { iss :: Text
    , sub :: Text
    , aud :: [Text]
    , exp :: IntDate
    , iat :: IntDate
    -- TODO: optional
    }
  deriving (Show, Eq)
