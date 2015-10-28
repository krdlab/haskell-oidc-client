{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GADTs #-}
{-|
    Module: Web.OIDC.Client.Context
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Context where

import Crypto.Random (CPRG)
import Data.ByteString (ByteString)
import Data.IORef (IORef)

import Web.OIDC.Client.Discovery.Provider (Provider)
import qualified Web.OIDC.Client.Discovery.Provider as P

-- | This data type represents information needed in the OpenID flow.
data OIDC = OIDC
    { authorizationSeverUrl :: String
    , tokenEndpoint         :: String
    , clientId              :: ByteString
    , clientSecret          :: ByteString
    , redirectUri           :: ByteString
    , provider              :: Provider
    , cprgRef               :: CPRGRef
    }

data CPRGRef where
    Ref   :: (CPRG g) => IORef g -> CPRGRef
    NoRef :: CPRGRef

def :: OIDC
def = OIDC
    { authorizationSeverUrl = error "You must specify authorizationSeverUrl"
    , tokenEndpoint         = error "You must specify tokenEndpoint"
    , clientId              = error "You must specify clientId"
    , clientSecret          = error "You must specify clientSecret"
    , redirectUri           = error "You must specify redirectUri"
    , provider              = error "You must specify provider"
    , cprgRef               = NoRef
    }

-- | Create OIDC.
--
-- First argument is used in a token decoding on ID Token Validation.
newOIDC :: CPRG g => IORef g -> OIDC
newOIDC ref = def { cprgRef = Ref ref }

newOIDC' :: OIDC
newOIDC' = def

setProvider
    :: Provider     -- ^ OP's information (obtain by 'discover')
    -> OIDC
    -> OIDC
setProvider p oidc =
    oidc { authorizationSeverUrl = P.authorizationEndpoint . P.configuration $ p
         , tokenEndpoint         = P.tokenEndpoint . P.configuration $ p
         , provider              = p
         }

setCredentials
    :: ByteString   -- ^ client ID
    -> ByteString   -- ^ client secret
    -> ByteString   -- ^ redirect URI
    -> OIDC
    -> OIDC
setCredentials cid secret redirect oidc =
    oidc { clientId     = cid
         , clientSecret = secret
         , redirectUri  = redirect
         }
