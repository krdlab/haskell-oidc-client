{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client
    ( getAuthenticationRequestUrl
    , requestTokens
    , getClaims
    , module Web.OIDC.Types
    , module Jose.Jwt
    ) where

import Control.Monad.Catch (MonadThrow)
import Data.Aeson (decode)
import Data.ByteString.Char8 (unwords)
import Data.Maybe (fromJust)
import Jose.Jwt (Jwt)
import qualified Jose.Jwt as Jwt
import Network.HTTP.Client (parseUrl, getUri, setQueryString, applyBasicAuth, urlEncodedBody, Request(..), newManager, httpLbs, responseBody)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.URI (URI)
import Prelude hiding (unwords)
import Web.OIDC.Types

getAuthenticationRequestUrl :: MonadThrow m => OIDC -> Scope -> RequestParameters -> m URI
getAuthenticationRequestUrl oidc scope params = do
    req <- parseUrl endpoint
    return $ getUri $ setQueryString query req
  where
    endpoint  = oidcAuthorizationSeverUrl oidc
    query     = requireds ++ params
    requireds =
        [ ("response_type", Just "code")
        , ("client_id",     Just $ oidcClientId oidc)
        , ("redirect_uri",  Just $ oidcRedirectUri oidc)
        , ("scope",         Just $ unwords $ "openid" : map toBS scope)
        ]
    toBS Profile = "profile"
    toBS Email = "email"
    toBS Address = "address"
    toBS Phone = "phone"
    toBS OfflineAccess = "offline_access"

-- TODO: error response

requestTokens :: OIDC -> Code -> IO Tokens
requestTokens oidc code = do
    req <- parseUrl endpoint
    let req' = applyBasicAuth cid csec $ urlEncodedBody body $ req { method = "POST" }
    mgr <- newManager tlsManagerSettings
    res <- httpLbs req' mgr
    return $ fromJust . decode $ responseBody res
  where
    endpoint = oidcTokenEndpoint oidc
    cid      = oidcClientId oidc
    csec     = oidcClientSecret oidc
    redirect = oidcRedirectUri oidc
    body     =
        [ ("grant_type",   "authorization_code")
        , ("code",         code)
        , ("redirect_uri", redirect)
        ]

getClaims :: Jwt -> Maybe Jwt.JwtClaims
getClaims jwt =
    case Jwt.decodeClaims (Jwt.unJwt jwt) of
        Right (_, c) -> return c
        Left  _      -> Nothing

-- TODO: ID Token Validation

