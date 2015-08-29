{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (decode, FromJSON, parseJSON, Value(..), (.:))
import Data.Maybe (fromJust)
import Network.HTTP.Client (newManager, parseUrl, httpLbs, responseBody)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Web.OIDC.Types (OP)

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

discover :: OP -> IO OpenIdConfiguration
discover uri = do
    req <- parseUrl uri
    mgr <- newManager tlsManagerSettings
    res <- httpLbs req mgr
    return $ fromJust . decode $ responseBody res

