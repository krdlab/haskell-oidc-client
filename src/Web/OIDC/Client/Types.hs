{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-|
    Module: Web.OIDC.Client.Types
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Types
    (
      ScopeValue(..)
    , Scope
    , State
    , Parameters
    , Code
    , IssuerLocation
    , OpenIdException(..)
    ) where

import Control.Applicative ((<*), (*>), (<|>))
import Control.Exception (Exception)
import Data.Aeson (FromJSON, parseJSON, withText)
import Data.Attoparsec.Text (parseOnly, endOfInput, string)
import Data.ByteString (ByteString)
import Data.List (isPrefixOf)
import Data.Text (Text, pack)
import Data.Typeable (Typeable)
import Jose.Jwt (JwtError)
import Network.HTTP.Client (HttpException)

type IssuerLocation = Text

data ScopeValue =
      OpenId
    | Profile
    | Email
    | Address
    | Phone
    | OfflineAccess
    deriving (Eq)

instance Show ScopeValue where
    show OpenId         = "openid"
    show Profile        = "profile"
    show Email          = "email"
    show Address        = "address"
    show Phone          = "phone"
    show OfflineAccess  = "offline_access"

instance Read ScopeValue where
    readsPrec _ s
        | "openid"          `isPrefixOf` s = [(OpenId, drop 6 s)]
        | "profile"         `isPrefixOf` s = [(Profile, drop 7 s)]
        | "email"           `isPrefixOf` s = [(Email, drop 5 s)]
        | "address"         `isPrefixOf` s = [(Address, drop 7 s)]
        | "phone"           `isPrefixOf` s = [(Phone, drop 5 s)]
        | "offline_access"  `isPrefixOf` s = [(OfflineAccess, drop 14 s)]
        | otherwise = []

instance FromJSON ScopeValue where
    parseJSON = withText "ScopeValue" (run parser)
      where
        run p t =
            case parseOnly (p <* endOfInput) t of
                Right r   -> return r
                Left  err -> fail $ "could not parse scope value: " ++ err
        parser =    parser' OpenId
                <|> parser' Profile
                <|> parser' Email
                <|> parser' Address
                <|> parser' Phone
                <|> parser' OfflineAccess
        parser' v = string (pack . show $ v) *> return v

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
