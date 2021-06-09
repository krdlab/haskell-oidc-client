{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BlockArguments #-}
{-|
    Module: Web.OIDC.Client.CodeFlow
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.CodeFlow
    (
      getAuthenticationRequestUrl
    , getValidTokens
    , prepareAuthenticationRequestUrl
    , requestTokens

    -- * For testing
    , validateClaims
    , getCurrentIntDate
    ) where

import           Control.Monad                      (unless, when)
import           Control.Monad.Catch                (MonadCatch, MonadThrow,
                                                     catch, throwM)
import           Control.Monad.IO.Class             (MonadIO, liftIO)
import           Data.Aeson                         (FromJSON, eitherDecode)
import qualified Data.ByteString.Char8              as B
import           Data.List                          (nub)
import           Data.Maybe                         (isNothing)
import           Data.Monoid                        ((<>))
import           Data.Text                          (Text, pack, unpack)
import           Data.Text.Encoding                 (decodeUtf8With)
import           Data.Text.Encoding.Error           (lenientDecode)
import           Data.Time.Clock.POSIX              (getPOSIXTime)
import qualified Jose.Jwt                           as Jwt
import           Network.HTTP.Client                (Manager, Request (..),
                                                     getUri, httpLbs,
                                                     responseBody,
                                                     setQueryString,
                                                     urlEncodedBody)
import           Network.URI                        (URI)
import           Control.Monad.Reader               (ReaderT(..), ask, lift)

import           Prelude                            hiding (exp)

import qualified Web.OIDC.Client.Discovery.Provider as P
import           Web.OIDC.Client.Internal           (parseUrl)
import qualified Web.OIDC.Client.Internal           as I
import           Web.OIDC.Client.Settings           (OIDC (..))
import           Web.OIDC.Client.Tokens             (IdTokenClaims (..), validateIdToken,
                                                     Tokens (..))
import           Web.OIDC.Client.Types              (Code, Nonce,
                                                     OpenIdException (..),
                                                     Parameters, Scope,
                                                     SessionStore (..), State,
                                                     openId)

-- | Make URL for Authorization Request after generating state and nonce from 'SessionStore'.
prepareAuthenticationRequestUrl
    :: (MonadThrow m, MonadCatch m)
    => SessionStore m
    -> Scope            -- ^ used to specify what are privileges requested for tokens. (use `ScopeValue`)
    -> Parameters       -- ^ Optional parameters
    -> ReaderT OIDC m URI
prepareAuthenticationRequestUrl store scope params = do
    (state, nonce') <- lift do
      state <- sessionStoreGenerate store
      nonce' <- sessionStoreGenerate store
      sessionStoreSave store state nonce'
      pure (state,nonce')

    getAuthenticationRequestUrl scope (Just state) $ params ++ [("nonce", Just nonce')]

-- | Get and validate access token and with code and state stored in the 'SessionStore'.
--   Then deletes session info by 'sessionStoreDelete'.
getValidTokens
    :: (MonadThrow m, MonadCatch m, MonadIO m, FromJSON a)
    => SessionStore m
    -> Manager
    -> State
    -> Code
    -> ReaderT OIDC m (Tokens a)
getValidTokens store mgr stateFromIdP code = do
    (state, savedNonce) <- lift (sessionStoreGet store)
    if state == Just stateFromIdP
      then do
          when (isNothing savedNonce) $ throwM $ ValidationException "Nonce is not saved!"
          result <- requestTokens savedNonce code mgr
          lift (sessionStoreDelete store)
          return result
      else throwM $ ValidationException $ "Inconsistent state: " <> decodeUtf8With lenientDecode stateFromIdP

-- | Make URL for Authorization Request.
{-# WARNING getAuthenticationRequestUrl "This function doesn't manage state and nonce. Use prepareAuthenticationRequestUrl only unless your IdP doesn't support state and/or nonce." #-}
getAuthenticationRequestUrl
    :: (MonadThrow m, MonadCatch m)
    => Scope            -- ^ used to specify what are privileges requested for tokens. (use `ScopeValue`)
    -> Maybe State      -- ^ used for CSRF mitigation. (recommended parameter)
    -> Parameters       -- ^ Optional parameters
    -> ReaderT OIDC m URI
getAuthenticationRequestUrl scope state params = do
    oidc <- ask

    let endpoint  = oidcAuthorizationServerUrl oidc
    let state' =
          case state of
            Just _  -> [("state", state)]
            Nothing -> []
    let requireds =
          [ ("response_type", Just "code")
          , ("client_id",     Just $ oidcClientId oidc)
          , ("redirect_uri",  Just $ oidcRedirectUri oidc)
          , ("scope",         Just $ B.pack . unwords . nub . map unpack $ openId:scope)
          ]
    let query     = requireds ++ state' ++ params

    req <- parseUrl endpoint `catch` I.rethrow
    return $ getUri $ setQueryString query req

-- TODO: error response

-- | Request and validate tokens.
--
-- This function requests ID Token and Access Token to a OP's token endpoint, and validates the received ID Token.
-- Returned `Tokens` value is a valid.
--
-- If a HTTP error has occurred or a tokens validation has failed, this function throws `OpenIdException`.
{-# WARNING requestTokens "This function doesn't manage state and nonce. Use getValidTokens only unless your IdP doesn't support state and/or nonce." #-}
requestTokens
    :: (MonadThrow m, MonadIO m, FromJSON a)
    => Maybe Nonce
    -> Code
    -> Manager
    -> ReaderT OIDC m (Tokens a)
requestTokens savedNonce code manager = do
    oidc <- ask

    let endpoint = oidcTokenEndpoint oidc
    let cid      = oidcClientId oidc
    let sec      = oidcClientSecret oidc
    let redirect = oidcRedirectUri oidc
    let body     =
          [ ("grant_type",    "authorization_code")
          , ("code",          code)
          , ("client_id",     cid)
          , ("client_secret", sec)
          , ("redirect_uri",  redirect)
          ]
    let getTokensJson = do
          req <- parseUrl endpoint
          let req' = urlEncodedBody body $ req { method = "POST" }
          res <- httpLbs req' manager
          return $ responseBody res

    json <- liftIO (getTokensJson `catch` I.rethrow)
    case eitherDecode json of
        Right ts -> validate savedNonce ts
        Left err -> throwM . JsonException $ pack err

validate
    :: (MonadThrow m, MonadIO m, FromJSON a)
    => Maybe Nonce
    -> I.TokensResponse
    -> ReaderT OIDC m (Tokens a)
validate savedNonce tres = do
    oidc <- ask
    let jwt' = I.idToken tres
    claims' <- validateIdToken oidc jwt'
    now <- getCurrentIntDate
    liftIO $ validateClaims
        (P.issuer . P.configuration . oidcProvider $ oidc)
        (decodeUtf8With lenientDecode . oidcClientId $ oidc)
        now
        savedNonce
        claims'
    return Tokens {
          accessToken  = I.accessToken tres
        , tokenType    = I.tokenType tres
        , idToken      = claims'
        , idTokenJwt   = jwt'
        , expiresIn    = I.expiresIn tres
        , refreshToken = I.refreshToken tres
        }

validateClaims
    :: Text
    -> Text
    -> Jwt.IntDate
    -> Maybe Nonce
    -> IdTokenClaims a
    -> IO ()
validateClaims issuer' clientId' now savedNonce claims' = do
    let iss' = iss claims'
    unless (iss' == issuer')
        $ throwM $ ValidationException $ "issuer from token \"" <> iss' <> "\" is different than expected issuer \"" <> issuer' <> "\""

    let aud' = aud claims'
    unless (clientId' `elem` aud')
        $ throwM $ ValidationException $ "our client \"" <> clientId' <> "\" isn't contained in the token's audience " <> (pack . show) aud'

    unless (now < exp claims')
        $ throwM $ ValidationException "received token has expired"

    unless (nonce claims' == savedNonce)
        $ throwM $ ValidationException "Inconsistent nonce"

getCurrentIntDate :: MonadIO m => m Jwt.IntDate
getCurrentIntDate = Jwt.IntDate <$> liftIO getPOSIXTime
