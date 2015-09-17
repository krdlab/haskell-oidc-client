{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client
    ( OIDC(..)
    , newOIDC
    , setProviderConf
    , setCredentials
    , getAuthenticationRequestUrl
    , requestTokens
    , module OIDC
    , module Jose.Jwt
    ) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM)
import Crypto.Random (CPRG)
import Data.Aeson (decode)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)
import Data.IORef (IORef, atomicModifyIORef')
import Data.List (nub)
import Data.Maybe (fromJust)
import Data.Text (pack)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Tuple (swap)
import qualified Jose.Jwk as Jwk
import Jose.Jwt (Jwt)
import qualified Jose.Jwt as Jwt
import Network.HTTP.Client (parseUrl, getUri, setQueryString, applyBasicAuth, urlEncodedBody, Request(..), Manager, httpLbs, responseBody)
import Network.URI (URI)
import Prelude hiding (exp)

import qualified Web.OIDC.Discovery as D
import Web.OIDC.Discovery.Providers as OIDC
import Web.OIDC.Types as OIDC
import qualified Web.OIDC.Client.Internal as I

data (CPRG g) => OIDC g = OIDC
    { authorizationSeverUrl :: String
    , tokenEndpoint         :: String
    , clientId              :: ByteString
    , clientSecret          :: ByteString
    , redirectUri           :: ByteString
    , providerConf          :: D.Configuration
    , cprgRef               :: Maybe (IORef g)
    }

newOIDC :: CPRG g => Maybe (IORef g) -> OIDC g
newOIDC ref = OIDC
    { authorizationSeverUrl = error "You must specify oidcAuthorizationSeverUrl"
    , tokenEndpoint         = error "You must specify oidcTokenEndpoint"
    , clientId              = error "You must specify oidcClientId"
    , clientSecret          = error "You must specify oidcClientSecret"
    , redirectUri           = error "You must specify oidcRedirectUri"
    , providerConf          = error "You must specify oidcProviderConf"
    , cprgRef               = ref
    }

setProviderConf :: CPRG g => D.Configuration -> OIDC g -> OIDC g
setProviderConf c oidc =
    oidc { authorizationSeverUrl    = D.authorizationEndpoint c
         , tokenEndpoint            = D.tokenEndpoint c
         , providerConf             = c
         }

setCredentials :: CPRG g => ByteString -> ByteString -> ByteString -> OIDC g -> OIDC g
setCredentials cid secret redirect oidc =
    oidc { clientId     = cid
         , clientSecret = secret
         , redirectUri  = redirect
         }

getAuthenticationRequestUrl :: (CPRG g, MonadThrow m) => OIDC g -> Scope -> Maybe State -> RequestParameters -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- parseUrl endpoint
    return $ getUri $ setQueryString query req
  where
    endpoint  = authorizationSeverUrl oidc
    query     = requireds ++ state' ++ params
    requireds =
        [ ("response_type", Just "code")
        , ("client_id",     Just $ clientId oidc)
        , ("redirect_uri",  Just $ redirectUri oidc)
        , ("scope",         Just $ B.pack . unwords . nub . map show $ OpenId:scope)
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
    endpoint = tokenEndpoint oidc
    cid      = clientId oidc
    csec     = clientSecret oidc
    redirect = redirectUri oidc
    body     =
        [ ("grant_type",   "authorization_code")
        , ("code",         code)
        , ("redirect_uri", redirect)
        ]

validate :: CPRG g => OIDC g -> I.TokensResponse -> Manager -> IO Tokens
validate oidc tres manager = do
    let jwt' = I.idToken tres
    claims' <- validateIdToken oidc jwt' manager
    let tokens = Tokens {
          OIDC.accessToken  = I.accessToken tres
        , OIDC.tokenType    = I.tokenType tres
        , OIDC.idToken      = IdToken { claims = toIdTokenClaims claims', jwt = jwt' }
        , OIDC.expiresIn    = I.expiresIn tres
        , OIDC.refreshToken = I.refreshToken tres
        }
    return tokens

getClaims :: MonadThrow m => Jwt -> m Jwt.JwtClaims
getClaims jwt' =
    case Jwt.decodeClaims (Jwt.unJwt jwt') of
        Right (_, c) -> return c
        Left  cause  -> throwM $ JwtExceptoin cause

-- TODO: oidcJwks :: Maybe (IORef [JWK])
getJwks :: String -> Manager -> IO L.ByteString
getJwks url mgr = do
    req <- parseUrl url
    res <- httpLbs req mgr
    return $ responseBody res

validateIdToken :: CPRG g => OIDC g -> Jwt -> Manager -> IO Jwt.JwtClaims
validateIdToken oidc jwt' mgr = do
    jsonJwk <- getJwks (D.jwksUri $ providerConf oidc) mgr    -- TODO
    case cprgRef oidc of
        Just crpg -> do
            decoded <- case Jwt.decodeClaims (Jwt.unJwt jwt') of
                Left  cause     -> throwM $ JwtExceptoin cause
                Right (jwth, _) ->
                    case jwth of
                        (Jwt.JwsH jws) -> do
                            let kid = Jwt.jwsKid jws
                                alg = Jwt.jwsAlg jws
                                jwk = getJwk kid jsonJwk
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) (Jwt.unJwt jwt'))
                        (Jwt.JweH jwe) -> do
                            let kid = Jwt.jweKid jwe
                                alg = Jwt.jweAlg jwe
                                enc = Jwt.jweEnc jwe
                                jwk = getJwk kid jsonJwk
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JweEncoding alg enc) (Jwt.unJwt jwt'))
                        _              -> error "not supported"
            case decoded of
                Left err -> throwM $ JwtExceptoin err
                Right _  -> return ()
        Nothing -> undefined -- TODO: request tokeninfo
    claims' <- getClaims jwt'
    unless (iss' claims' == issuer')
        $ throwM $ ValidationException "issuer"
    unless (clientId' `elem` aud' claims')
        $ throwM $ ValidationException "audience"
    expire <- exp' claims'
    now <- Jwt.IntDate <$> getPOSIXTime
    unless (now < expire)
        $ throwM $ ValidationException "expire"
    return claims'
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

    iss' c = fromJust (Jwt.jwtIss c)
    aud' c = fromJust (Jwt.jwtAud c)
    exp' c =
        case Jwt.jwtExp c of
            Nothing -> throwM $ ValidationException "exp claim was not found"
            Just ex -> return ex
    issuer' = pack . D.issuer . providerConf $ oidc
    clientId' = decodeUtf8 . clientId $ oidc

