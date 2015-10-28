{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Discovery.Provider
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Discovery.Provider where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:))
import Jose.Jwk (Jwk)

import Web.OIDC.Client.Types (ScopeValue, IssuerLocation)

-- | An OpenID Provider information
data Provider = Provider { configuration :: Configuration, jwkSet :: [Jwk] }

-- | An OpenID Provider Configuration
data Configuration = Configuration
    { issuer                            :: IssuerLocation
    , authorizationEndpoint             :: String
    , tokenEndpoint                     :: String
    , userinfoEndpoint                  :: String
    , revocationEndpoint                :: String
    , jwksUri                           :: String
    , responseTypesSupported            :: [String]
    , subjectTypesSupported             :: [String]
    , idTokenSigningAlgValuesSupported  :: [String]
    , scopesSupported                   :: [ScopeValue]
    , tokenEndpointAuthMethodsSupported :: [String]
    , claimsSupported                   :: [String]
    }
  deriving (Show, Eq)

instance FromJSON Configuration where
    parseJSON (Object o) = Configuration
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
