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
    , Parameters
    , Code
    , IssuerLocation
    , OpenIdException(..)
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

type Parameters = [(ByteString, Maybe ByteString)]

type Code = ByteString

data OpenIdException =
      DiscoveryException Text
    | InternalHttpException HttpException
    | JwtExceptoin JwtError
    | ValidationException Text
  deriving (Show, Typeable)

instance Exception OpenIdException
