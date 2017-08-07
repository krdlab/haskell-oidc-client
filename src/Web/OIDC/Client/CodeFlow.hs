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

import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow, throwM, MonadCatch, catch)
import Data.Aeson (eitherDecode)
import qualified Data.ByteString.Char8 as B
import Data.List (nub)
import Data.Monoid ((<>))
import Data.Text (Text, pack, unpack)
import Data.Text.Encoding (decodeUtf8)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Jose.Jwt (Jwt)
import qualified Jose.Jwt as Jwt
import Network.HTTP.Client (getUri, setQueryString, urlEncodedBody, Request(..), Manager, httpLbs, responseBody)
import Network.URI (URI)

import Web.OIDC.Client.Settings (OIDC(..))
import qualified Web.OIDC.Client.Discovery.Provider as P
import qualified Web.OIDC.Client.Internal as I
import Web.OIDC.Client.Internal (parseUrl)
import Web.OIDC.Client.Tokens (Tokens(..), IdToken(..))
import Web.OIDC.Client.Types (Scope, openId, Code, State, Parameters, OpenIdException(..))

-- | Make URL for Authorization Request.
getAuthenticationRequestUrl
    :: (MonadThrow m, MonadCatch m)
    => OIDC
    -> Scope            -- ^ used to specify what are privileges requested for tokens. (use `ScopeValue`)
    -> Maybe State      -- ^ used for CSRF mitigation. (recommended parameter)
    -> Parameters       -- ^ Optional parameters
    -> m URI
getAuthenticationRequestUrl oidc scope state params = do
    req <- parseUrl endpoint `catch` I.rethrow
    return $ getUri $ setQueryString query req
  where
    endpoint  = oidcAuthorizationServerUrl oidc
    query     = requireds ++ state' ++ params
    requireds =
        [ ("response_type", Just "code")
        , ("client_id",     Just $ oidcClientId oidc)
        , ("redirect_uri",  Just $ oidcRedirectUri oidc)
        , ("scope",         Just $ B.pack . unwords . nub . map unpack $ openId:scope)
        ]
    state' =
        case state of
            Just _  -> [("state", state)]
            Nothing -> []

-- TODO: error response

-- | Request and validate tokens.
--
-- This function requests ID Token and Access Token to a OP's token endpoint, and validates the received ID Token.
-- Returned `Tokens` value is a valid.
--
-- If a HTTP error has occurred or a tokens validation has failed, this function throws `OpenIdException`.
requestTokens :: OIDC -> Code -> Manager -> IO Tokens
requestTokens oidc code manager = do
    json <- getTokensJson `catch` I.rethrow
    case eitherDecode json of
        Right ts -> validate oidc ts
        Left err -> error $ "failed to decode tokens json: " ++ err     -- TODO: Exception
  where
    getTokensJson = do
        req <- parseUrl endpoint
        let req' = urlEncodedBody body $ req { method = "POST" }
        res <- httpLbs req' manager
        return $ responseBody res
    endpoint = oidcTokenEndpoint oidc
    cid      = oidcClientId oidc
    sec      = oidcClientSecret oidc
    redirect = oidcRedirectUri oidc
    body     =
        [ ("grant_type",    "authorization_code")
        , ("code",          code)
        , ("client_id",     cid)
        , ("client_secret", sec)
        , ("redirect_uri",  redirect)
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
validateIdToken oidc jwt' = do
    let jwks = P.jwkSet . oidcProvider $ oidc
        token = Jwt.unJwt jwt'
    decoded <- Jwt.decode jwks Nothing token
    case decoded of
        Right _  -> return ()
        Left err -> throwM $ JwtExceptoin err

getClaims :: MonadThrow m => Jwt -> m Jwt.JwtClaims
getClaims jwt' = case Jwt.decodeClaims (Jwt.unJwt jwt') of
                Right (_, c) -> return c
                Left  cause  -> throwM $ JwtExceptoin cause

validateClaims :: Text -> Text -> Jwt.IntDate -> Jwt.JwtClaims -> IO ()
validateClaims issuer' clientId' now claims' = do
    iss' <- getIss claims'
    unless (iss' == issuer')
        $ throwM $ ValidationException $ "issuer from token \"" <> iss' <> "\" different than expected issuer \"" <> issuer' <> "\""

    aud' <- getAud claims'
    unless (clientId' `elem` aud')
        $ throwM $ ValidationException $ "our client \"" <> clientId' <> "\" isn't contained in the token's audience " <> (pack . show) aud'

    exp' <- getExp claims'
    unless (now < exp')
        $ throwM $ ValidationException "received token has expired"
  where
    getIss c = get Jwt.jwtIss c "'iss' claim was not found"
    getAud c = get Jwt.jwtAud c "'aud' claim was not found"
    getExp c = get Jwt.jwtExp c "'exp' claim was not found"
    get f v msg = case f v of
        Just v' -> return v'
        Nothing -> throwM $ ValidationException msg

getCurrentIntDate :: IO Jwt.IntDate
getCurrentIntDate = Jwt.IntDate <$> getPOSIXTime
