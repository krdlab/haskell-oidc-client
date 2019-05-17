{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Internal
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Internal where

import           Control.Applicative            ( (<|>) )
import           Control.Monad                  ( mzero )
import           Control.Monad.Catch            ( MonadCatch
                                                , MonadThrow
                                                , throwM
                                                )
import           Data.Aeson                     ( FromJSON
                                                , Value(..)
                                                , parseJSON
                                                , (.:)
                                                , (.:?)
                                                )
import           Data.Aeson.Types               ( Parser )
import           Data.Text                      ( Text
                                                , unpack
                                                )
import           Data.Text.Read                 ( decimal )
import           Jose.Jwt                       ( Jwt )
import           Network.HTTP.Client            ( HttpException
                                                , Request
                                                , parseRequest
                                                )
import           Prelude                 hiding ( exp )
import           Web.OIDC.Client.Types          ( OpenIdException
                                                  ( InternalHttpException
                                                  )
                                                )

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
        <*> ((o .:? "expires_in") <|> (textToInt =<< (o .:? "expires_in")))
        <*>  o .:? "refresh_token"
    parseJSON _          = mzero

textToInt :: Maybe Text -> Parser (Maybe Integer)
textToInt (Just t) = case decimal t of
  Right (i, _) -> pure $ Just i
  Left _ ->
    fail "expires_in: expected a decimal text, encountered a non decimal text"
textToInt _ = pure Nothing

rethrow :: (MonadCatch m) => HttpException -> m a
rethrow = throwM . InternalHttpException

parseUrl :: MonadThrow m => Text -> m Request
parseUrl = Network.HTTP.Client.parseRequest . unpack
