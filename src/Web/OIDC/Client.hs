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
    , validateIdToken
    , module OIDC
    , module Jose.Jwt
    ) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM)
import Data.Aeson (decode)
import Data.ByteString.Char8 (unwords)
import Data.ByteString.Lazy (ByteString)
import Data.List (nub)
import Data.Maybe (fromJust, fromMaybe)
import Data.Text (pack)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX (getPOSIXTime)
import qualified Jose.Jwk as Jwk
import Jose.Jwt (Jwt)
import qualified Jose.Jwt as Jwt
import Network.HTTP.Client (parseUrl, getUri, setQueryString, applyBasicAuth, urlEncodedBody, Request(..), Manager, httpLbs, responseBody)
import Network.URI (URI)
import Prelude hiding (unwords, exp)
import Crypto.Random (CPRG)

import Web.OIDC.Discovery as OIDC
import Web.OIDC.Discovery.Providers as OIDC
import Web.OIDC.Types as OIDC

getAuthenticationRequestUrl :: MonadThrow m => OIDC -> Scope -> Maybe State -> RequestParameters -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- parseUrl endpoint
    return $ getUri $ setQueryString query req
  where
    endpoint  = oidcAuthorizationSeverUrl oidc
    query     = requireds ++ state' ++ params
    requireds =
        [ ("response_type", Just "code")
        , ("client_id",     Just $ oidcClientId oidc)
        , ("redirect_uri",  Just $ oidcRedirectUri oidc)
        , ("scope",         Just $ unwords . nub . map toBS $ OpenId:scope)
        ]
    toBS OpenId         = "openid"
    toBS Profile        = "profile"
    toBS Email          = "email"
    toBS Address        = "address"
    toBS Phone          = "phone"
    toBS OfflineAccess  = "offline_access"
    state' =
        case state of
            Just _  -> [("state", state)]
            Nothing -> []

-- TODO: error response

requestTokens :: OIDC -> Code -> Manager -> IO Tokens
requestTokens oidc code mgr = do
    req <- parseUrl endpoint
    let req' = applyBasicAuth cid csec $ urlEncodedBody body $ req { method = "POST" }
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

getClaims :: MonadThrow m => Jwt -> m Jwt.JwtClaims
getClaims jwt =
    case Jwt.decodeClaims (Jwt.unJwt jwt) of
        Right (_, c) -> return c
        Left  cause  -> throwM $ JwtExceptoin cause

getJwks :: String -> Manager -> IO ByteString
getJwks url mgr = do
    req <- parseUrl url
    res <- httpLbs req mgr
    return $ responseBody res

validateIdToken :: CPRG g => g -> OIDC -> Jwt -> Manager -> IO (Jwt.JwtClaims, g)
validateIdToken g oidc jwt mgr = do
    jsonJwk <- getJwks (jwksUri $ oidcProviderConf oidc) mgr
    decoded <- case Jwt.decodeClaims (Jwt.unJwt jwt) of
        Left  cause     -> throwM $ JwtExceptoin cause
        Right (jwth, _) ->
            case jwth of
                (Jwt.JwsH jws) -> do
                    let kid = Jwt.jwsKid jws
                        alg = Jwt.jwsAlg jws
                        jwk = getJwk kid jsonJwk
                    return $ Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) (Jwt.unJwt jwt)
                (Jwt.JweH jwe) -> do
                    let kid = Jwt.jweKid jwe
                        alg = Jwt.jweAlg jwe
                        enc = Jwt.jweEnc jwe
                        jwk = getJwk kid jsonJwk
                    return $ Jwt.decode g [jwk] (Just $ Jwt.JweEncoding alg enc) (Jwt.unJwt jwt)
                _              -> error "not supported"
    case fst decoded of
        Left err -> throwM $ JwtExceptoin err
        Right _  -> return ()
    claims <- getClaims jwt
    unless (iss claims == issuer')
        $ throwM $ ValidationException "issuer"
    unless (clientId `elem` aud claims)
        $ throwM $ ValidationException "audience"
    expire <- exp claims
    now <- Jwt.IntDate <$> getPOSIXTime
    unless (now < expire)
        $ throwM $ ValidationException "expire"
    return (claims, snd decoded)
  where
    getJwk kid json =
        case kid of
            Just keyId ->
                let jwk = fromJust $ decode json in head $ filter (eq keyId) (Jwk.keys jwk) -- TODO
            Nothing    ->
                let jwk = fromJust $ decode json in jwk
      where
        eq e jwk = case Jwk.jwkId jwk of
                       Just i  -> i == e
                       Nothing -> False

    iss c = fromMaybe "" (Jwt.jwtIss c)
    aud c = fromMaybe [] (Jwt.jwtAud c)
    exp c =
        case Jwt.jwtExp c of
            Nothing -> throwM $ ValidationException "exp claim was not found"
            Just ex -> return ex
    issuer' = pack . issuer . oidcProviderConf $ oidc
    clientId = decodeUtf8 . oidcClientId $ oidc

