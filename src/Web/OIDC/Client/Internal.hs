{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Internal
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Internal where

import Control.Monad (mzero)
import Control.Monad.Catch (MonadThrow, throwM, MonadCatch)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), (.:?))
import Data.Maybe (fromJust)
import Data.Text (Text, unpack)
import Jose.Jwt (Jwt, JwtClaims(..))
import Network.HTTP.Client (HttpException, parseUrl, Request)
import Prelude hiding (exp)
import Web.OIDC.Client.Tokens (IdTokenClaims(..))
import Web.OIDC.Client.Types (OpenIdException(InternalHttpException))

data TokensResponse = TokensResponse
    { accessToken   :: !Text
    , tokenType     :: !Text
    , idToken       :: !Jwt
    , expiresIn     :: !(Maybe Integer)
    , refreshToken  :: !(Maybe Text)
    }
  deriving (Show, Eq)

instance FromJSON TokensResponse where
    parseJSON (Object o) = TokensResponse
        <$> o .:  "access_token"
        <*> o .:  "token_type"
        <*> o .:  "id_token"
        <*> o .:? "expires_in"
        <*> o .:? "refresh_token"
    parseJSON _          = mzero

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
parseUrl = Network.HTTP.Client.parseUrl . unpack
