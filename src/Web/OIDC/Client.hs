{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client
    ( OIDC
    , newOIDC
    , setProvider
    , setCredentials
    , getAuthenticationRequestUrl
    , requestTokens
    , module OIDC
    , module Jose.Jwt
    ) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM, MonadCatch, catch)
import Crypto.Random (CPRG)
import Data.Aeson (decode)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef')
import Data.List (nub)
import Data.Maybe (fromMaybe, fromJust)
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

import qualified Web.OIDC.Client.Internal as I
import qualified Web.OIDC.Discovery as D
import Web.OIDC.Types as OIDC

data (CPRG g) => OIDC g = OIDC
    { authorizationSeverUrl :: String
    , tokenEndpoint         :: String
    , clientId              :: ByteString
    , clientSecret          :: ByteString
    , redirectUri           :: ByteString
    , provider              :: D.Provider
    , cprgRef               :: Maybe (IORef g)
    }

newOIDC :: CPRG g => Maybe (IORef g) -> OIDC g
newOIDC ref = OIDC
    { authorizationSeverUrl = error "You must specify authorizationSeverUrl"
    , tokenEndpoint         = error "You must specify tokenEndpoint"
    , clientId              = error "You must specify clientId"
    , clientSecret          = error "You must specify clientSecret"
    , redirectUri           = error "You must specify redirectUri"
    , provider              = error "You must specify provider"
    , cprgRef               = ref
    }

setProvider :: CPRG g => D.Provider -> OIDC g -> OIDC g
setProvider p oidc =
    oidc { authorizationSeverUrl    = D.authorizationEndpoint . D.configuration $ p
         , tokenEndpoint            = D.tokenEndpoint . D.configuration $ p
         , provider                 = p
         }

setCredentials :: CPRG g => ByteString -> ByteString -> ByteString -> OIDC g -> OIDC g
setCredentials cid secret redirect oidc =
    oidc { clientId     = cid
         , clientSecret = secret
         , redirectUri  = redirect
         }

getAuthenticationRequestUrl :: (CPRG g, MonadThrow m, MonadCatch m) => OIDC g -> Scope -> Maybe State -> RequestParameters -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- parseUrl endpoint `catch` rethrow
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
    json <- getTokensJson `catch` rethrow
    case decode json of
        Just ts -> validate oidc ts
        Nothing -> error "failed to decode tokens json" -- TODO
  where
    getTokensJson = do
        req <- parseUrl endpoint
        let req' = applyBasicAuth cid sec $ urlEncodedBody body $ req { method = "POST" }
        res <- httpLbs req' manager
        return $ responseBody res
    endpoint = tokenEndpoint oidc
    cid      = clientId oidc
    sec      = clientSecret oidc
    redirect = redirectUri oidc
    body     =
        [ ("grant_type",   "authorization_code")
        , ("code",         code)
        , ("redirect_uri", redirect)
        ]

validate :: CPRG g => OIDC g -> I.TokensResponse -> IO Tokens
validate oidc tres = do
    let jwt' = I.idToken tres
    claims' <- validateIdToken oidc jwt'
    let tokens = Tokens {
          OIDC.accessToken  = I.accessToken tres
        , OIDC.tokenType    = I.tokenType tres
        , OIDC.idToken      = IdToken { claims = toIdTokenClaims claims', jwt = jwt' }
        , OIDC.expiresIn    = I.expiresIn tres
        , OIDC.refreshToken = I.refreshToken tres
        }
    return tokens

validateIdToken :: CPRG g => OIDC g -> Jwt -> IO Jwt.JwtClaims
validateIdToken oidc jwt' = do
    case cprgRef oidc of
        Just crpg -> do
            decoded <- case Jwt.decodeClaims (Jwt.unJwt jwt') of
                Left  cause     -> throwM $ JwtExceptoin cause
                Right (jwth, _) ->
                    case jwth of
                        (Jwt.JwsH jws) -> do
                            let kid = Jwt.jwsKid jws
                                alg = Jwt.jwsAlg jws
                                jwk = getJwk kid (D.jwkSet . provider $ oidc)
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) (Jwt.unJwt jwt'))
                        (Jwt.JweH jwe) -> do
                            let kid = Jwt.jweKid jwe
                                alg = Jwt.jweAlg jwe
                                enc = Jwt.jweEnc jwe
                                jwk = getJwk kid (D.jwkSet . provider $ oidc)
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JweEncoding alg enc) (Jwt.unJwt jwt'))
                        _ -> error "not supported"
            case decoded of
                Left err -> throwM $ JwtExceptoin err
                Right _  -> return ()
        Nothing -> error "not implemented" -- TODO: request tokeninfo

    claims' <- getClaims

    unless (getIss claims' == issuer')
        $ throwM $ ValidationException "issuer"

    unless (clientId' `elem` getAud claims')
        $ throwM $ ValidationException "audience"

    expire <- getExp claims'
    now    <- getCurrentTime
    unless (now < expire)
        $ throwM $ ValidationException "expire"

    return claims'
  where
    getJwk kid jwks = head $ case kid of
                                 Just keyId -> filter (eq keyId) jwks
                                 Nothing    -> jwks
      where
        eq e jwk = fromMaybe False ((==) e <$> Jwk.jwkId jwk)

    getClaims = case Jwt.decodeClaims (Jwt.unJwt jwt') of
                    Right (_, c) -> return c
                    Left  cause  -> throwM $ JwtExceptoin cause

    issuer'   = pack . D.issuer . D.configuration . provider $ oidc
    clientId' = decodeUtf8 . clientId $ oidc

    getIss c = fromJust (Jwt.jwtIss c)
    getAud c = fromJust (Jwt.jwtAud c)
    getExp c = case Jwt.jwtExp c of
                   Just e  -> return e
                   Nothing -> throwM $ ValidationException "exp claim was not found"
    getCurrentTime = Jwt.IntDate <$> getPOSIXTime

