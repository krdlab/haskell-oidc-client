{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client
    ( getAuthenticationRequestUrl
    , requestTokens
    , module OIDC
    , module Jose.Jwt
    ) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM)
import Data.Aeson (decode)
import Data.ByteString.Char8 (unwords)
import Data.ByteString.Lazy (ByteString)
import Data.IORef (atomicModifyIORef')
import Data.List (nub)
import Data.Maybe (fromJust, fromMaybe)
import Data.Text (pack)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Tuple (swap)
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
import qualified Web.OIDC.Client.Internal as I

getAuthenticationRequestUrl :: (CPRG g, MonadThrow m) => OIDC g -> Scope -> Maybe State -> RequestParameters -> m URI
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
        , ("scope",         Just $ unwords . nub . map I.toBS $ OpenId:scope)
        ]
    state' =
        case state of
            Just _  -> [("state", state)]
            Nothing -> []

-- TODO: error response

requestTokens :: CPRG g => OIDC g -> Code -> Manager -> IO Tokens
requestTokens oidc code manager = do
    req <- parseUrl endpoint
    let req' = applyBasicAuth cid csec $ urlEncodedBody body $ req { method = "POST" }

    res <- httpLbs req' manager
    let tokensJson = fromJust . decode $ responseBody res

    validate oidc tokensJson manager
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

validate :: CPRG g => OIDC g -> I.TokensResponse -> Manager -> IO Tokens
validate oidc tres manager = do
    let jwt = I.idToken tres
    claims <- validateIdToken oidc jwt manager
    let tokens = Tokens {
          OIDC.accessToken  = I.accessToken tres
        , OIDC.tokenType    = I.tokenType tres
        , OIDC.idToken      = IdToken { itClaims = toIdTokenClaims claims, itJwt = jwt }
        , OIDC.expiresIn    = I.expiresIn tres
        , OIDC.refreshToken = I.refreshToken tres
        }
    return tokens

getClaims :: MonadThrow m => Jwt -> m Jwt.JwtClaims
getClaims jwt =
    case Jwt.decodeClaims (Jwt.unJwt jwt) of
        Right (_, c) -> return c
        Left  cause  -> throwM $ JwtExceptoin cause

-- TODO: oidcJwks :: Maybe (IORef [JWK])
getJwks :: String -> Manager -> IO ByteString
getJwks url mgr = do
    req <- parseUrl url
    res <- httpLbs req mgr
    return $ responseBody res

validateIdToken :: CPRG g => OIDC g -> Jwt -> Manager -> IO Jwt.JwtClaims
validateIdToken oidc jwt mgr = do
    jsonJwk <- getJwks (jwksUri $ oidcProviderConf oidc) mgr    -- TODO
    case oidcCPRGRef oidc of
        Just crpg -> do
            decoded <- case Jwt.decodeClaims (Jwt.unJwt jwt) of
                Left  cause     -> throwM $ JwtExceptoin cause
                Right (jwth, _) ->
                    case jwth of
                        (Jwt.JwsH jws) -> do
                            let kid = Jwt.jwsKid jws
                                alg = Jwt.jwsAlg jws
                                jwk = getJwk kid jsonJwk
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) (Jwt.unJwt jwt))
                        (Jwt.JweH jwe) -> do
                            let kid = Jwt.jweKid jwe
                                alg = Jwt.jweAlg jwe
                                enc = Jwt.jweEnc jwe
                                jwk = getJwk kid jsonJwk
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JweEncoding alg enc) (Jwt.unJwt jwt))
                        _              -> error "not supported"
            case decoded of
                Left err -> throwM $ JwtExceptoin err
                Right _  -> return ()
        Nothing -> undefined -- TODO: request tokeninfo
    claims <- getClaims jwt
    unless (iss claims == issuer')
        $ throwM $ ValidationException "issuer"
    unless (clientId `elem` aud claims)
        $ throwM $ ValidationException "audience"
    expire <- exp claims
    now <- Jwt.IntDate <$> getPOSIXTime
    unless (now < expire)
        $ throwM $ ValidationException "expire"
    return claims
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

