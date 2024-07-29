{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Settings
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Settings
    (
      OIDC(..)
    , def
    , newOIDC
    , setCredentials
    ) where

import           Data.ByteString                    (ByteString)
import           Data.Text                          (Text)

import           Web.OIDC.Client.Discovery.Provider (Provider)
import qualified Web.OIDC.Client.Discovery.Provider as P

-- | This data type represents information needed in the OpenID flow.
data OIDC = OIDC
    { oidcAuthorizationServerUrl :: Text
    , oidcTokenEndpoint          :: Text
    , oidcClientId               :: ByteString
    , oidcClientSecret           :: ByteString
    , oidcRedirectUri            :: ByteString
    , oidcProvider               :: Provider
    } deriving (Eq, Show)

def :: OIDC
def = OIDC
    { oidcAuthorizationServerUrl = error "You must specify authorizationServerUrl"
    , oidcTokenEndpoint          = error "You must specify tokenEndpoint"
    , oidcClientId               = error "You must specify clientId"
    , oidcClientSecret           = error "You must specify clientSecret"
    , oidcRedirectUri            = error "You must specify redirectUri"
    , oidcProvider               = error "You must specify provider"
    }

newOIDC
    :: Provider     -- ^ OP's information (obtained by 'Web.OIDC.Client.Discovery.discover')
    -> OIDC
newOIDC p =
    def { oidcAuthorizationServerUrl = P.authorizationEndpoint . P.configuration $ p
        , oidcTokenEndpoint          = P.tokenEndpoint . P.configuration $ p
        , oidcProvider               = p
        }

setCredentials
    :: ByteString   -- ^ client ID
    -> ByteString   -- ^ client secret
    -> ByteString   -- ^ redirect URI (the HTTP endpont on your server that will receive a response from OP)
    -> OIDC
    -> OIDC
setCredentials cid secret redirect oidc =
    oidc { oidcClientId     = cid
         , oidcClientSecret = secret
         , oidcRedirectUri  = redirect
         }
