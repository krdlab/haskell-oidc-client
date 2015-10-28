{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.CodeFlow
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.CodeFlow
    (
      getAuthenticationRequestUrl
    , requestTokens
    ) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM, MonadCatch, catch)
import Data.Aeson (decode)
import qualified Data.ByteString.Char8 as B
import Data.IORef (atomicModifyIORef')
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

import Web.OIDC.Client.Settings (OIDC(..), CPRGRef(..))
import qualified Web.OIDC.Client.Discovery.Provider as P
import qualified Web.OIDC.Client.Internal as I
import Web.OIDC.Client.Tokens (Tokens(..), IdToken(..))
import Web.OIDC.Client.Types (Scope, ScopeValue(..), Code, State, Parameters, OpenIdException(..))

getAuthenticationRequestUrl :: (MonadThrow m, MonadCatch m) => OIDC -> Scope -> Maybe State -> Parameters -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- parseUrl endpoint `catch` I.rethrow
    return $ getUri $ setQueryString query req
  where
    endpoint  = oidcAuthorizationSeverUrl oidc
    query     = requireds ++ state' ++ params
    requireds =
        [ ("response_type", Just "code")
        , ("client_id",     Just $ oidcClientId oidc)
        , ("redirect_uri",  Just $ oidcRedirectUri oidc)
        , ("scope",         Just $ B.pack . unwords . nub . map show $ OpenId:scope)
        ]
    state' =
        case state of
            Just _  -> [("state", state)]
            Nothing -> []

-- TODO: error response

-- | Request and obtain valid tokens.
--
-- This function requests ID Token and Access Token to a OP's token endpoint, and validates the received ID Token.
-- Returned value is a valid tokens.
requestTokens :: OIDC -> Code -> Manager -> IO Tokens
requestTokens oidc code manager = do
    json <- getTokensJson `catch` I.rethrow
    case decode json of
        Just ts -> validate oidc ts
        Nothing -> error "failed to decode tokens json" -- TODO
  where
    getTokensJson = do
        req <- parseUrl endpoint
        let req' = applyBasicAuth cid sec $ urlEncodedBody body $ req { method = "POST" }
        res <- httpLbs req' manager
        return $ responseBody res
    endpoint = oidcTokenEndpoint oidc
    cid      = oidcClientId oidc
    sec      = oidcClientSecret oidc
    redirect = oidcRedirectUri oidc
    body     =
        [ ("grant_type",   "authorization_code")
        , ("code",         code)
        , ("redirect_uri", redirect)
        ]

validate :: OIDC -> I.TokensResponse -> IO Tokens
validate oidc tres = do
    let jwt' = I.idToken tres
    claims' <- validateIdToken oidc jwt'
    let tokens = Tokens {
          accessToken  = I.accessToken tres
        , tokenType    = I.tokenType tres
        , idToken      = IdToken { claims = I.toIdTokenClaims claims', jwt = jwt' }
        , expiresIn    = I.expiresIn tres
        , refreshToken = I.refreshToken tres
        }
    return tokens

validateIdToken :: OIDC -> Jwt -> IO Jwt.JwtClaims
validateIdToken oidc jwt' = do
    case oidcCPRGRef oidc of
        Ref crpg -> do
            decoded <- case Jwt.decodeClaims (Jwt.unJwt jwt') of
                Left  cause     -> throwM $ JwtExceptoin cause
                Right (jwth, _) ->
                    case jwth of
                        (Jwt.JwsH jws) -> do
                            let kid = Jwt.jwsKid jws
                                alg = Jwt.jwsAlg jws
                                jwk = getJwk kid (P.jwkSet . oidcProvider $ oidc)
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) (Jwt.unJwt jwt'))
                        (Jwt.JweH jwe) -> do
                            let kid = Jwt.jweKid jwe
                                alg = Jwt.jweAlg jwe
                                enc = Jwt.jweEnc jwe
                                jwk = getJwk kid (P.jwkSet . oidcProvider $ oidc)
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JweEncoding alg enc) (Jwt.unJwt jwt'))
                        _ -> error "not supported"
            case decoded of
                Left err -> throwM $ JwtExceptoin err
                Right _  -> return ()
        NoRef -> error "not implemented" -- TODO: request tokeninfo

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

    issuer'   = pack . P.issuer . P.configuration . oidcProvider $ oidc
    clientId' = decodeUtf8 . oidcClientId $ oidc

    getIss c = fromJust (Jwt.jwtIss c)
    getAud c = fromJust (Jwt.jwtAud c)
    getExp c = case Jwt.jwtExp c of
                   Just e  -> return e
                   Nothing -> throwM $ ValidationException "exp claim was not found"
    getCurrentTime = Jwt.IntDate <$> getPOSIXTime
