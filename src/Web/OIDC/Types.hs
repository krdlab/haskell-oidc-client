{-# LANGUAGE OverloadedStrings #-}

module Web.OIDC.Types
    ( Scope
    , ScopeValue(..)
    , Parameter
    , RequestParameters
    , Code
    , OIDC(..)
    , newOIDC
    , Tokens(..)
    ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), (.:?))
import Data.ByteString (ByteString)
import Data.Default (Default, def)
import Jose.Jwt (Jwt)

data ScopeValue = OpenId | Profile | Email | Address | Phone | OfflineAccess
    deriving (Show, Eq)

type Scope = [ScopeValue]
type Parameter = ByteString
type RequestParameters = [(Parameter, Maybe ByteString)]
type Code = ByteString

data OIDC = OIDC
    { oidcAuthorizationSeverUrl :: String
    , oidcTokenEndpoint :: String
    , oidcClientId :: ByteString
    , oidcClientSecret :: ByteString
    , oidcRedirectUri :: ByteString
    }
  deriving (Show, Eq)

newOIDC :: OIDC
newOIDC = OIDC
    { oidcAuthorizationSeverUrl = error "You must specify oidcAuthorizationSeverUrl"
    , oidcTokenEndpoint = error "You must specify oidcTokenEndpoint"
    , oidcClientId = error "You must specify oidcClientId"
    , oidcClientSecret = error "You must specify oidcClientSecret"
    , oidcRedirectUri = error "You must specify oidcRedirectUri"
    }

instance Default OIDC where
    def = newOIDC

data Tokens = Tokens
    { accessToken :: !String
    , tokenType :: !String
    , idToken :: !Jwt
    , expiresIn :: !(Maybe Integer)
    , refreshToken :: !(Maybe String)
    }
  deriving (Show, Eq)

instance FromJSON Tokens where
    parseJSON (Object o) = Tokens
        <$> o .:  "access_token"
        <*> o .:  "token_type"
        <*> o .:  "id_token"
        <*> o .:? "expires_in"
        <*> o .:? "refresh_token"
    parseJSON _          = mzero

