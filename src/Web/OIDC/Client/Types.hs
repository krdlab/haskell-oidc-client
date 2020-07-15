{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}
{-|
    Module: Web.OIDC.Client.Types
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Types
    (
      ScopeValue
    , openId, profile, email, address, phone, offlineAccess
    , Scope
    , State
    , Nonce
    , Parameters
    , Code
    , IssuerLocation
    , OpenIdException(..)
    , SessionStore (..)
    ) where

import           Control.Exception   (Exception)
import           Data.ByteString     (ByteString)
import           Data.Text           (Text)
import           Data.Typeable       (Typeable)
import           Jose.Jwt            (JwtError)
import           Network.HTTP.Client (HttpException)

type IssuerLocation = Text

type ScopeValue = Text

openId, profile, email, address, phone, offlineAccess :: ScopeValue
openId        = "openid"
profile       = "profile"
email         = "email"
address       = "address"
phone         = "phone"
offlineAccess = "offline_access"

type Scope = [ScopeValue]

type State = ByteString

type Nonce = ByteString

type Parameters = [(ByteString, Maybe ByteString)]

type Code = ByteString

data OpenIdException =
      DiscoveryException Text
    | InternalHttpException HttpException
    | JsonException Text
    | UnsecuredJwt ByteString
    | JwtException JwtError
    | ValidationException Text
    | UnknownState
    | MissingNonceInResponse
    | MismatchedNonces
  deriving (Show, Typeable)

instance Exception OpenIdException

-- | Manages state and nonce.
--   (Maybe 'OIDC' should have them)
data SessionStore m = SessionStore
    { sessionStoreGenerate :: m ByteString
    -- ^ Generate state and nonce at random
    , sessionStoreSave :: State -> Nonce -> m ()
    , sessionStoreGet :: State -> m (Maybe Nonce)
    -- ^ Returns 'Nothing' if 'State' is unknown
    , sessionStoreDelete :: m ()
    -- ^ Should delete at least nonce
    }
