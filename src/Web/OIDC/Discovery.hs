{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), decode)
import Data.Maybe (fromJust)
import Network.HTTP.Client (Manager, parseUrl, httpLbs, responseBody)
import Web.OIDC.Types

data Configuration = Configuration
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

discover :: OP -> Manager -> IO Configuration
discover uri manager = do
    req <- parseUrl uri
    res <- httpLbs req manager
    return $ fromJust . decode $ responseBody res
