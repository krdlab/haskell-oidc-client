{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GADTs #-}
{-|
    Module: Web.OIDC.Client.Settings
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Settings
    (
      OIDC(..)
    , CPRGRef(..)
    , def
    , newOIDC
    , newOIDC'
    , setProvider
    , setCredentials
    ) where

import Crypto.Random (CPRG)
import Data.ByteString (ByteString)
import Data.IORef (IORef)
import Data.Text (Text)

import Web.OIDC.Client.Discovery.Provider (Provider)
import qualified Web.OIDC.Client.Discovery.Provider as P

-- | This data type represents information needed in the OpenID flow.
data OIDC = OIDC
    { oidcAuthorizationSeverUrl :: Text
    , oidcTokenEndpoint         :: Text
    , oidcClientId              :: ByteString
    , oidcClientSecret          :: ByteString
    , oidcRedirectUri           :: ByteString
    , oidcProvider              :: Provider
    , oidcCPRGRef               :: CPRGRef
    }

data CPRGRef where
    Ref   :: (CPRG g) => IORef g -> CPRGRef
    NoRef :: CPRGRef

def :: OIDC
def = OIDC
    { oidcAuthorizationSeverUrl = error "You must specify authorizationSeverUrl"
    , oidcTokenEndpoint         = error "You must specify tokenEndpoint"
    , oidcClientId              = error "You must specify clientId"
    , oidcClientSecret          = error "You must specify clientSecret"
    , oidcRedirectUri           = error "You must specify redirectUri"
    , oidcProvider              = error "You must specify provider"
    , oidcCPRGRef               = NoRef
    }

-- | Create OIDC.
--
-- First argument is used in a token decoding on ID Token Validation.
newOIDC :: CPRG g => IORef g -> OIDC
newOIDC ref = def { oidcCPRGRef = Ref ref }

newOIDC' :: OIDC
newOIDC' = def

setProvider
    :: Provider     -- ^ OP's information (obtain by 'discover')
    -> OIDC
    -> OIDC
setProvider p oidc =
    oidc { oidcAuthorizationSeverUrl = P.authorizationEndpoint . P.configuration $ p
         , oidcTokenEndpoint         = P.tokenEndpoint . P.configuration $ p
         , oidcProvider              = p
         }

setCredentials
    :: ByteString   -- ^ client ID
    -> ByteString   -- ^ client secret
    -> ByteString   -- ^ redirect URI
    -> OIDC
    -> OIDC
setCredentials cid secret redirect oidc =
    oidc { oidcClientId     = cid
         , oidcClientSecret = secret
         , oidcRedirectUri  = redirect
         }
