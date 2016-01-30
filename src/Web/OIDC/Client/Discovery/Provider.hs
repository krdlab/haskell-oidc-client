{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-|
    Module: Web.OIDC.Client.Discovery.Provider
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Discovery.Provider
    (
      Provider(..)
    , Configuration(..)
    ) where

import Data.Aeson.TH (deriveFromJSON, Options(..), defaultOptions)
import Data.Aeson.Types (camelTo2)
import Data.Text (Text)
import Jose.Jwk (Jwk)

import Web.OIDC.Client.Types (ScopeValue, IssuerLocation)

-- | An OpenID Provider information
data Provider = Provider { configuration :: Configuration, jwkSet :: [Jwk] }

-- | An OpenID Provider Configuration
data Configuration = Configuration
    { issuer                            :: IssuerLocation
    , authorizationEndpoint             :: Text
    , tokenEndpoint                     :: Text
    , userinfoEndpoint                  :: Maybe Text
    , revocationEndpoint                :: Maybe Text
    , jwksUri                           :: Text
    , responseTypesSupported            :: [Text]
    , subjectTypesSupported             :: [Text]
    , idTokenSigningAlgValuesSupported  :: Maybe [Text] -- TODO: REQUIRED
    , scopesSupported                   :: Maybe [ScopeValue]
    , tokenEndpointAuthMethodsSupported :: Maybe [Text]
    , claimsSupported                   :: Maybe [Text]
    }
    -- http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  deriving (Show, Eq)

$(deriveFromJSON defaultOptions{fieldLabelModifier = camelTo2 '_'} ''Configuration)
