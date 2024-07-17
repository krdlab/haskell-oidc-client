{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
{-|
    Module: Web.OIDC.Client.Discovery.Provider
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Discovery.Provider
    (
      Provider(..)
    , Configuration(..)
    , JwsAlgJson(..)
    ) where

import           Data.Aeson            (FromJSON, parseJSON, withText)
import           Data.Aeson.TH         (Options (..), defaultOptions,
                                        deriveFromJSON)
import           Data.Aeson.Types      (camelTo2)
import           Data.Text             (Text)
import           Jose.Jwa              (JwsAlg (..))
import           Jose.Jwk              (Jwk)

import           Web.OIDC.Client.Types (IssuerLocation, ScopeValue)

-- | An OpenID Provider information
data Provider = Provider { configuration :: Configuration, jwkSet :: [Jwk] } deriving (Eq, Show)

data JwsAlgJson = JwsAlgJson { getJwsAlg :: JwsAlg } | Unsupported Text deriving (Show, Eq)

instance FromJSON JwsAlgJson where
    parseJSON = withText "JwsAlgJson" $ \case
        "HS256" -> pure $ JwsAlgJson HS256
        "HS384" -> pure $ JwsAlgJson HS384
        "HS512" -> pure $ JwsAlgJson HS512
        "RS256" -> pure $ JwsAlgJson RS256
        "RS384" -> pure $ JwsAlgJson RS384
        "RS512" -> pure $ JwsAlgJson RS512
        "ES256" -> pure $ JwsAlgJson ES256
        "ES384" -> pure $ JwsAlgJson ES384
        "ES512" -> pure $ JwsAlgJson ES512
        "none"  -> pure $ JwsAlgJson None
        other   -> pure $ Unsupported other


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
    , idTokenSigningAlgValuesSupported  :: [JwsAlgJson]
    , scopesSupported                   :: Maybe [ScopeValue]
    , tokenEndpointAuthMethodsSupported :: Maybe [Text]
    , claimsSupported                   :: Maybe [Text]
    }
    -- http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  deriving (Show, Eq)

$(deriveFromJSON defaultOptions{fieldLabelModifier = camelTo2 '_'} ''Configuration)
