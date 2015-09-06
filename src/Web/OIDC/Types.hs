{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-|
Module: Web.OIDC.Types
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Types
    ( OP
    , Scope
    , ScopeValue(..)
    , State
    , Parameter
    , RequestParameters
    , Code
    , OpenIdConfiguration(..)
    , OIDC(..)
    , newOIDC
    , Tokens(..)
    , OpenIdException(..)
    ) where

import Control.Applicative ((<$>), (<*>))
import Control.Exception (Exception)
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), (.:?))
import Data.ByteString (ByteString)
import Data.Default (Default, def)
import Data.Typeable (Typeable)
import Jose.Jwt (Jwt, JwtError)

type OP = String

data ScopeValue =
      OpenId
    | Profile
    | Email
    | Address
    | Phone
    | OfflineAccess
    deriving (Show, Eq)

type Scope = [ScopeValue]

type State = ByteString

type Parameter = ByteString

type RequestParameters = [(Parameter, Maybe ByteString)]

type Code = ByteString

data OpenIdConfiguration = OpenIdConfiguration
    { issuer                            :: String
    , authorizationEndpoint             :: String
    , tokenEndpoint                     :: String
    , userinfoEndpoint                  :: String
    , revocationEndpoint                :: String
    , jwksUri                           :: String
    , responseTypesSupported            :: [String]
    , subjectTypesSupported             :: [String]
    , idTokenSigningAlgValuesSupported  :: [String]
    , scopesSupported                   :: [String]  -- TODO: Scope
    , tokenEndpointAuthMethodsSupported :: [String]
    , claimsSupported                   :: [String]
    }
  deriving (Show, Eq)

instance FromJSON OpenIdConfiguration where
    parseJSON (Object o) = OpenIdConfiguration
        <$> o .: "issuer"
        <*> o .: "authorization_endpoint"
        <*> o .: "token_endpoint"
        <*> o .: "userinfo_endpoint"
        <*> o .: "revocation_endpoint"
        <*> o .: "jwks_uri"
        <*> o .: "response_types_supported"
        <*> o .: "subject_types_supported"
        <*> o .: "id_token_signing_alg_values_supported"
        <*> o .: "scopes_supported"
        <*> o .: "token_endpoint_auth_methods_supported"
        <*> o .: "claims_supported"
    parseJSON _ = mzero

data OIDC = OIDC
    { oidcAuthorizationSeverUrl :: String
    , oidcTokenEndpoint :: String
    , oidcClientId :: ByteString
    , oidcClientSecret :: ByteString
    , oidcRedirectUri :: ByteString
    , oidcProviderConf :: OpenIdConfiguration
    }
  deriving (Show, Eq)

newOIDC :: OIDC
newOIDC = OIDC
    { oidcAuthorizationSeverUrl = error "You must specify oidcAuthorizationSeverUrl"
    , oidcTokenEndpoint = error "You must specify oidcTokenEndpoint"
    , oidcClientId = error "You must specify oidcClientId"
    , oidcClientSecret = error "You must specify oidcClientSecret"
    , oidcRedirectUri = error "You must specify oidcRedirectUri"
    , oidcProviderConf = error "You must specify oidcProviderConf"
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

data OpenIdException =
      JwtExceptoin JwtError
    | ValidationException String
  deriving (Show, Typeable)

instance Exception OpenIdException

