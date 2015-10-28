{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client.Tokens
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client.Tokens where

import Data.Maybe (fromJust)
import Data.Text (unpack)
import Jose.Jwt (Jwt, JwtClaims(..), IntDate)
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

toIdTokenClaims :: JwtClaims -> IdTokenClaims
toIdTokenClaims c = IdTokenClaims
    { iss =     unpack $ fromJust (jwtIss c)
    , sub =     unpack $ fromJust (jwtSub c)
    , aud = map unpack $ fromJust (jwtAud c)
    , exp =              fromJust (jwtExp c)
    , iat =              fromJust (jwtIat c)
    }


