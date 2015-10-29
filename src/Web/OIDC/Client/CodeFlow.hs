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

    -- * For testing
    , validateClaims
    , getCurrentIntDate
    ) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM, MonadCatch, catch)
import Crypto.Random (CPRG)
import Data.Aeson (decode)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import Data.IORef (IORef, atomicModifyIORef')
import Data.List (nub)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Tuple (swap)
import qualified Jose.Jwk as Jwk
import Jose.Jwt (Jwt)
import qualified Jose.Jwt as Jwt
import Network.HTTP.Client (getUri, setQueryString, applyBasicAuth, urlEncodedBody, Request(..), Manager, httpLbs, responseBody)
import Network.URI (URI)

import Web.OIDC.Client.Settings (OIDC(..), CPRGRef(..))
import qualified Web.OIDC.Client.Discovery.Provider as P
import qualified Web.OIDC.Client.Internal as I
import Web.OIDC.Client.Internal (parseUrl)
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
    validateIdToken oidc jwt'
    claims' <- getClaims jwt'
    now <- getCurrentIntDate
    validateClaims
        (P.issuer . P.configuration . oidcProvider $ oidc)
        (decodeUtf8 . oidcClientId $ oidc)
        now
        claims'
    return Tokens {
          accessToken  = I.accessToken tres
        , tokenType    = I.tokenType tres
        , idToken      = IdToken { claims = I.toIdTokenClaims claims', jwt = jwt' }
        , expiresIn    = I.expiresIn tres
        , refreshToken = I.refreshToken tres
        }

validateIdToken :: OIDC -> Jwt -> IO ()
validateIdToken oidc jwt' =
    case oidcCPRGRef oidc of
        Ref cprg -> do
            let token = Jwt.unJwt jwt'
            decoded <- case Jwt.decodeClaims token of
                Left  err       -> throwM $ JwtExceptoin err
                Right (jwth, _) -> decodeToken oidc cprg token jwth
            case decoded of
                Left err -> throwM $ JwtExceptoin err
                Right _  -> return ()
        NoRef -> error "not implemented" -- TODO: request tokeninfo

decodeToken
    :: CPRG g
    => OIDC
    -> IORef g
    -> ByteString       -- ^ ID Token (JWT format)
    -> Jwt.JwtHeader
    -> IO (Either Jwt.JwtError Jwt.JwtContent)
decodeToken oidc cprg token jwth =
    case jwth of
        (Jwt.JwsH jws) -> do
            let kid = Jwt.jwsKid jws
                alg = Jwt.jwsAlg jws
                jwk = getJwk kid (P.jwkSet . oidcProvider $ oidc)
            atomicModifyIORef' cprg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) token)
        (Jwt.JweH jwe) -> do
            let kid = Jwt.jweKid jwe
                alg = Jwt.jweAlg jwe
                enc = Jwt.jweEnc jwe
                jwk = getJwk kid (P.jwkSet . oidcProvider $ oidc)
            atomicModifyIORef' cprg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JweEncoding alg enc) token)
        _ -> error "not supported" -- TODO: exception
  where
    getJwk kid jwks = head $ case kid of
                                 Just keyId -> filter (eq keyId) jwks
                                 Nothing    -> jwks
      where
        eq e jwk = fromMaybe False ((==) e <$> Jwk.jwkId jwk)

getClaims :: MonadThrow m => Jwt -> m Jwt.JwtClaims
getClaims jwt' = case Jwt.decodeClaims (Jwt.unJwt jwt') of
                Right (_, c) -> return c
                Left  cause  -> throwM $ JwtExceptoin cause

validateClaims :: Text -> Text -> Jwt.IntDate -> Jwt.JwtClaims -> IO ()
validateClaims issuer' clientId' now claims' = do
    iss' <- getIss claims'
    unless (iss' == issuer')
        $ throwM $ ValidationException "issuer"

    aud' <- getAud claims'
    unless (clientId' `elem` aud')
        $ throwM $ ValidationException "audience"

    exp' <- getExp claims'
    unless (now < exp')
        $ throwM $ ValidationException "expire"
  where
    getIss c = get Jwt.jwtIss c "'iss' claim was not found"
    getAud c = get Jwt.jwtAud c "'aud' claim was not found"
    getExp c = get Jwt.jwtExp c "'exp' claim was not found"
    get f v msg = case f v of
        Just v' -> return v'
        Nothing -> throwM $ ValidationException msg

getCurrentIntDate :: IO Jwt.IntDate
getCurrentIntDate = Jwt.IntDate <$> getPOSIXTime
