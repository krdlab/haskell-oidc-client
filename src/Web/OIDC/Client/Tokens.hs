{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

{-|
    Module: Web.OIDC.Client.Tokens
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Tokens
    (
      Tokens(..)
    , IdTokenClaims(..)
    ) where

import           Control.Applicative ((<|>))
import           Data.Aeson         (FromJSON (parseJSON), Value (Object),
                                     withObject, (.:), (.:?))
import           Data.ByteString    (ByteString)
import           Data.Text          (Text)
import           Data.Text.Encoding (encodeUtf8)
import           GHC.Generics       (Generic)
import           Jose.Jwt           (IntDate)
import           Prelude            hiding (exp)

data Tokens a = Tokens
    { accessToken  :: Text
    , tokenType    :: Text
    , idToken      :: IdTokenClaims a
    , expiresIn    :: Maybe Integer
    , refreshToken :: Maybe Text
    }
  deriving (Show, Eq)

-- | Claims required for an <https://openid.net/specs/openid-connect-core-1_0.html#IDToken ID Token>,
--   plus recommended claims (nonce) and other custom claims.
data IdTokenClaims a = IdTokenClaims
    { iss         :: !Text
    , sub         :: !Text
    , aud         :: ![Text]
    , exp         :: !IntDate
    , iat         :: !IntDate
    , nonce       :: !(Maybe ByteString)
    , otherClaims :: !a
    }
  deriving (Show, Eq, Generic)


instance FromJSON a => FromJSON (IdTokenClaims a) where
    parseJSON = withObject "IdTokenClaims" $ \o ->
        IdTokenClaims
            <$> o .: "iss"
            <*> o .: "sub"
            <*> (o .: "aud" <|> ((:[]) <$> (o .: "aud")))
            <*> o .: "exp"
            <*> o .: "iat"
            <*> (fmap encodeUtf8 <$> o .:? "nonce")
            <*> parseJSON (Object o)
