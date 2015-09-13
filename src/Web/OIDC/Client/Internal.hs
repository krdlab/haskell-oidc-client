{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client.Internal
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client.Internal where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), (.:?))
import Data.ByteString (ByteString)
import Jose.Jwt (Jwt)

import Web.OIDC.Types (ScopeValue(..))

toBS :: ScopeValue -> ByteString
toBS OpenId         = "openid"
toBS Profile        = "profile"
toBS Email          = "email"
toBS Address        = "address"
toBS Phone          = "phone"
toBS OfflineAccess  = "offline_access"

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
