{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Internal
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Internal where

import           Control.Applicative    ((<|>))
import           Control.Monad          (mzero)
import           Control.Monad.Catch    (MonadCatch, MonadThrow, throwM)
import           Data.Aeson             (FromJSON, Value (..), parseJSON, (.:),
                                         (.:?))
import           Data.Maybe             (fromJust)
import           Data.Scientific        (Scientific, floatingOrInteger)
import           Data.Text              (Text, unpack)
import           Data.Text.Read         (decimal)
import           Jose.Jwt               (Jwt, JwtClaims (..))
import           Network.HTTP.Client    (HttpException, Request, parseRequest)
import           Prelude                hiding (exp)
import           Web.OIDC.Client.Tokens (IdTokenClaims (..))
import           Web.OIDC.Client.Types  (OpenIdException (InternalHttpException))

data TokensResponse = TokensResponse
    { accessToken  :: !Text
    , tokenType    :: !Text
    , idToken      :: !Jwt
    , expiresIn    :: !(Maybe Integer)
    , refreshToken :: !(Maybe Text)
    }
  deriving (Show, Eq)

instance FromJSON TokensResponse where
    parseJSON (Object o) = TokensResponse
        <$>  o .:  "access_token"
        <*>  o .:  "token_type"
        <*>  o .:  "id_token"
        <*> (o .:? "expires_in" <|> ((>>= numberToInt) <$> (o .:? "expires_in")) <|> (>>= textToInt) <$> (o .:? "expires_in"))
        <*>  o .:? "refresh_token"
    parseJSON _          = mzero

numberToInt :: Scientific -> Maybe Integer
numberToInt s = case floatingOrInteger s of
    Left  r -> Just $ floor (r :: Double)
    Right i -> Just i

textToInt :: Text -> Maybe Integer
textToInt t = case decimal t of
    Right (i, _) -> Just i
    Left  _      -> Nothing

rethrow :: (MonadCatch m) => HttpException -> m a
rethrow = throwM . InternalHttpException

toIdTokenClaims :: JwtClaims -> IdTokenClaims
toIdTokenClaims c = IdTokenClaims   -- FIXME: fromJust
    { iss = fromJust (jwtIss c)
    , sub = fromJust (jwtSub c)
    , aud = fromJust (jwtAud c)
    , exp = fromJust (jwtExp c)
    , iat = fromJust (jwtIat c)
    }

parseUrl :: MonadThrow m => Text -> m Request
parseUrl = Network.HTTP.Client.parseRequest . unpack
