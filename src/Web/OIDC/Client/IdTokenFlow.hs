{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.CodeFlow
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.IdTokenFlow
    (
      getAuthenticationRequestUrl
    , getValidIdTokenClaims
    , prepareAuthenticationRequestUrl
    ) where

import           Control.Monad                      (when)
import           Control.Exception                  (throwIO, catch)
import           Control.Monad.IO.Class             (MonadIO, liftIO)
import           Data.Aeson                         (FromJSON)
import qualified Data.ByteString.Char8              as B
import           Data.List                          (nub)
import           Data.Maybe                         (isNothing, fromMaybe)
import           Data.Monoid                        ((<>))
import           Data.Text                          (unpack)
import           Data.Text.Encoding                 (decodeUtf8)
import qualified Jose.Jwt                           as Jwt
import           Network.HTTP.Client                (getUri, setQueryString)
import           Network.URI                        (URI)

import           Prelude                            hiding (exp)

import           Web.OIDC.Client.Internal           (parseUrl)
import qualified Web.OIDC.Client.Internal           as I
import           Web.OIDC.Client.Settings           (OIDC (..))
import           Web.OIDC.Client.Tokens             (IdTokenClaims (..), validateIdToken)
import           Web.OIDC.Client.Types              (OpenIdException (..),
                                                     Parameters, Scope,
                                                     SessionStore (..), State,
                                                     openId)

-- | Make URL for Authorization Request after generating state and nonce from 'SessionStore'.
prepareAuthenticationRequestUrl
    :: (MonadIO m)
    => SessionStore m
    -> OIDC
    -> Scope            -- ^ used to specify what are privileges requested for tokens. (use `ScopeValue`)
    -> Parameters       -- ^ Optional parameters
    -> m URI
prepareAuthenticationRequestUrl store oidc scope params = do
    state <- sessionStoreGenerate store
    nonce' <- sessionStoreGenerate store
    sessionStoreSave store state nonce'
    getAuthenticationRequestUrl oidc scope (Just state) $ params ++ [("nonce", Just nonce')]

-- | Get and validate access token and with code and state stored in the 'SessionStore'.
--   Then deletes session info by 'sessionStoreDelete'.
getValidIdTokenClaims
    :: (MonadIO m, FromJSON a)
    => SessionStore m
    -> OIDC
    -> State
    -> m B.ByteString
    -> m (IdTokenClaims a)
getValidIdTokenClaims store oidc stateFromIdP getIdToken = do
    (state, savedNonce) <- sessionStoreGet store
    if state == Just stateFromIdP
      then do
          when (isNothing savedNonce) $ liftIO $ throwIO $ ValidationException "Nonce is not saved!"
          jwt <- Jwt.Jwt <$> getIdToken
          sessionStoreDelete store
          idToken <- liftIO $ validateIdToken oidc jwt
          when (fromMaybe True $ (/=) <$> savedNonce <*> nonce idToken)
                $ liftIO
                $ throwIO
                $ ValidationException "Nonce does not match request."
          pure idToken
      else liftIO $ throwIO $ ValidationException $ "Incosistent state: " <> decodeUtf8 stateFromIdP

-- | Make URL for Authorization Request.
{-# WARNING getAuthenticationRequestUrl "This function doesn't manage state and nonce. Use prepareAuthenticationRequestUrl only unless your IdP doesn't support state and/or nonce." #-}
getAuthenticationRequestUrl
    :: (MonadIO m)
    => OIDC
    -> Scope            -- ^ used to specify what are privileges requested for tokens. (use `ScopeValue`)
    -> Maybe State      -- ^ used for CSRF mitigation. (recommended parameter)
    -> Parameters       -- ^ Optional parameters
    -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- liftIO $ parseUrl endpoint `catch` I.rethrow
    return $ getUri $ setQueryString query req
  where
    endpoint  = oidcAuthorizationServerUrl oidc
    query     = requireds ++ state' ++ params
    requireds =
        [ ("response_type", Just "id_token")
        , ("response_mode", Just "form_post")
        , ("client_id",     Just $ oidcClientId oidc)
        , ("redirect_uri",  Just $ oidcRedirectUri oidc)
        , ("scope",         Just . B.pack . unwords . nub . map unpack $ openId:scope)
        ]
    state' =
        case state of
            Just _  -> [("state", state)]
            Nothing -> []
