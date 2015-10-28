{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GADTs #-}
{-|
Module: Web.OIDC.Client
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client
    (
    -- * Client Obtains ID Token and Access Token
      OIDC
    , newOIDC
    , newOIDC'
    , setProvider
    , setCredentials
    , getAuthenticationRequestUrl
    , requestTokens

    -- * Types
    , Provider
    , Scope, ScopeValue(..)
    , Code, State
    , Parameters
    , Tokens(..), IdToken(..), IdTokenClaims(..)

    -- * Exception
    , OpenIdException(..)

    -- * Re-exports
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
import qualified Web.OIDC.Client.Types as OT
import Web.OIDC.Client.Types (Provider, Scope, ScopeValue(..), Code, State, Parameters, Tokens(..), IdToken(..), IdTokenClaims(..), OpenIdException(..))

-- | This data type represents information needed in the OpenID flow.
data OIDC = OIDC
    { authorizationSeverUrl :: String
    , tokenEndpoint         :: String
    , clientId              :: ByteString
    , clientSecret          :: ByteString
    , redirectUri           :: ByteString
    , provider              :: Provider
    , cprgRef               :: CPRGRef
    }

data CPRGRef where
    Ref   :: (CPRG g) => IORef g -> CPRGRef
    NoRef :: CPRGRef

def :: OIDC
def = OIDC
    { authorizationSeverUrl = error "You must specify authorizationSeverUrl"
    , tokenEndpoint         = error "You must specify tokenEndpoint"
    , clientId              = error "You must specify clientId"
    , clientSecret          = error "You must specify clientSecret"
    , redirectUri           = error "You must specify redirectUri"
    , provider              = error "You must specify provider"
    , cprgRef               = NoRef
    }

-- | Create OIDC.
--
-- First argument is used in a token decoding on ID Token Validation.
newOIDC :: CPRG g => IORef g -> OIDC
newOIDC ref = def { cprgRef = Ref ref }

newOIDC' :: OIDC
newOIDC' = def

setProvider
    :: Provider     -- ^ OP's information (obtain by 'discover')
    -> OIDC
    -> OIDC
setProvider p oidc =
    oidc { authorizationSeverUrl = OT.authorizationEndpoint . OT.configuration $ p
         , tokenEndpoint         = OT.tokenEndpoint . OT.configuration $ p
         , provider              = p
         }

setCredentials
    :: ByteString   -- ^ client ID
    -> ByteString   -- ^ client secret
    -> ByteString   -- ^ redirect URI
    -> OIDC
    -> OIDC
setCredentials cid secret redirect oidc =
    oidc { clientId     = cid
         , clientSecret = secret
         , redirectUri  = redirect
         }

getAuthenticationRequestUrl :: (MonadThrow m, MonadCatch m) => OIDC -> Scope -> Maybe State -> Parameters -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- parseUrl endpoint `catch` OT.rethrow
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

-- | Request and obtain valid tokens.
--
-- This function requests ID Token and Access Token to a OP's token endpoint, and validates the received ID Token.
-- Returned value is a valid tokens.
requestTokens :: OIDC -> Code -> Manager -> IO Tokens
requestTokens oidc code manager = do
    json <- getTokensJson `catch` OT.rethrow
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

validate :: OIDC -> I.TokensResponse -> IO Tokens
validate oidc tres = do
    let jwt' = I.idToken tres
    claims' <- validateIdToken oidc jwt'
    let tokens = Tokens {
          accessToken  = I.accessToken tres
        , tokenType    = I.tokenType tres
        , idToken      = IdToken { claims = OT.toIdTokenClaims claims', jwt = jwt' }
        , expiresIn    = I.expiresIn tres
        , refreshToken = I.refreshToken tres
        }
    return tokens

validateIdToken :: OIDC -> Jwt -> IO Jwt.JwtClaims
validateIdToken oidc jwt' = do
    case cprgRef oidc of
        Ref crpg -> do
            decoded <- case Jwt.decodeClaims (Jwt.unJwt jwt') of
                Left  cause     -> throwM $ JwtExceptoin cause
                Right (jwth, _) ->
                    case jwth of
                        (Jwt.JwsH jws) -> do
                            let kid = Jwt.jwsKid jws
                                alg = Jwt.jwsAlg jws
                                jwk = getJwk kid (OT.jwkSet . provider $ oidc)
                            atomicModifyIORef' crpg $ \g -> swap (Jwt.decode g [jwk] (Just $ Jwt.JwsEncoding alg) (Jwt.unJwt jwt'))
                        (Jwt.JweH jwe) -> do
                            let kid = Jwt.jweKid jwe
                                alg = Jwt.jweAlg jwe
                                enc = Jwt.jweEnc jwe
                                jwk = getJwk kid (OT.jwkSet . provider $ oidc)
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

    issuer'   = pack . OT.issuer . OT.configuration . provider $ oidc
    clientId' = decodeUtf8 . clientId $ oidc

    getIss c = fromJust (Jwt.jwtIss c)
    getAud c = fromJust (Jwt.jwtAud c)
    getExp c = case Jwt.jwtExp c of
                   Just e  -> return e
                   Nothing -> throwM $ ValidationException "exp claim was not found"
    getCurrentTime = Jwt.IntDate <$> getPOSIXTime

