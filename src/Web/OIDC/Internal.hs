{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Internal
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Internal where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), (.:?))
import Jose.Jwt (Jwt)

data TokensResponse = TokensResponse
    { accessToken :: !String
    , tokenType :: !String
    , idToken :: !Jwt
    , expiresIn :: !(Maybe Integer)
    , refreshToken :: !(Maybe String)
    }
  deriving (Show, Eq)

instance FromJSON TokensResponse where
    parseJSON (Object o) = TokensResponse
        <$> o .:  "access_token"
        <*> o .:  "token_type"
        <*> o .:  "id_token"
        <*> o .:? "expires_in"
        <*> o .:? "refresh_token"
    parseJSON _          = mzero
