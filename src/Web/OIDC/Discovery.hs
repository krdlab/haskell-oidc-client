{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery
    ( Provider(..)
    , Configuration(..)
    , discover
    , module P
    ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (mzero)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), decode)
import Data.Maybe (fromMaybe)
import Data.Monoid (mempty)
import qualified Jose.Jwk as Jwk
import Jose.Jwk (Jwk)
import Network.HTTP.Client (Manager, parseUrl, httpLbs, responseBody)
import Web.OIDC.Types
import Web.OIDC.Discovery.Providers as P

-- | An OpenID provider
data Provider = Provider { configuration :: Configuration, jwkSet :: [Jwk] }

-- | An OpenID Provider Configuration
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

discover
    :: OP           -- ^ OpenID Provider's Issuer location
    -> Manager
    -> IO Provider
discover endpoint manager = do
    conf <- getConfiguration
    case conf of
        Just c  -> Provider c . jwks <$> getJwkSetJson (jwksUri c)
        Nothing -> error "failed to decode" -- TODO
  where
    getConfiguration = do
        req <- parseUrl endpoint
        res <- httpLbs req manager
        return $ decode $ responseBody res
    getJwkSetJson url = do
        req <- parseUrl url
        res <- httpLbs req manager
        return $ responseBody res
    jwks j = fromMaybe single (Jwk.keys <$> decode j)
      where
        single = case decode j of
                     Just k  -> return k
                     Nothing -> mempty

