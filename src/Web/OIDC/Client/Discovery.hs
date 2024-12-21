{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Discovery
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Discovery
    (
      discover

    -- * OpenID Provider Issuers
    , google

    -- * OpenID Provider Configuration Information
    , Provider(..)
    , Configuration(..)

    -- * For testing
    , generateDiscoveryUrl
    ) where

import           Control.Monad.Catch                (catch, throwM)
import           Data.Aeson                         (eitherDecode)
import           Data.ByteString                    (append, isSuffixOf)
import           Data.Foldable                      (foldMap)
import           Data.Monoid                        ((<>), First (..), getFirst)
import           Data.Text                          (pack, unpack)
import           Data.Text.Encoding                 (decodeLatin1)
import           Data.Time.Format                   (defaultTimeLocale,
                                                     parseTimeM)
import qualified Jose.Jwk                           as Jwk
import           Network.HTTP.Client                (Manager, Request, httpLbs,
                                                     path, responseBody,
                                                     responseHeaders)

import           Web.OIDC.Client.Discovery.Issuers  (google)
import           Web.OIDC.Client.Discovery.Provider (Configuration (..),
                                                     Provider (..))
import           Web.OIDC.Client.Internal           (parseUrl, rethrow)
import           Web.OIDC.Client.Types              (IssuerLocation,
                                                     OpenIdException (..))

-- | This function obtains OpenID Provider configuration and JWK set, and infers
-- 'validUntil' from the HTTP Expires headers.
discover
    :: IssuerLocation   -- ^ OpenID Provider's Issuer location
    -> Manager
    -> IO Provider
discover location manager = do
    (conf, confValidity) <- getConfiguration `catch` rethrow
    case conf of
        Right c   -> do
            (json, keysValidity) <- getJwkSetJson (jwksUri c) `catch` rethrow
            case jwks json of
                Right keys -> return $ Provider
                    { configuration = c
                    , jwkSet = keys
                    , validUntil = bothValidUntil confValidity keysValidity
                    }
                Left  err  -> throwM $ DiscoveryException ("Failed to decode JwkSet: " <> pack err)
        Left  err -> throwM $ DiscoveryException ("Failed to decode configuration: " <> pack err)
  where
    getConfiguration = do
        req <- generateDiscoveryUrl location
        res <- httpLbs req manager
        return (eitherDecode $ responseBody res, getValidity res)

    getValidity res =
        getFirst $ foldMap (First . getValidityFromHeader) $ responseHeaders res

    getValidityFromHeader (header, value)
        -- cache-control overrides expires if present, but cache-control
        -- involves doing calculations with the date and the age header, whereas
        -- expires is much simpler to use
        | header == "expires" =
            parseTimeM True defaultTimeLocale
              -- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires#syntax
              "%a, %d %b %Y %H:%M:%S %Z"
              -- note that headers are in Latin-1 even if the body is encoded
              -- with something else
              $ unpack $ decodeLatin1 value
        | otherwise = Nothing

    bothValidUntil a Nothing = a
    bothValidUntil Nothing b = b
    bothValidUntil (Just a) (Just b) = Just (min a b)

    getJwkSetJson url = do
        req <- parseUrl url
        res <- httpLbs req manager
        return (responseBody res, getValidity res)

    jwks j = Jwk.keys <$> eitherDecode j

generateDiscoveryUrl :: IssuerLocation -> IO Request
generateDiscoveryUrl location = do
    req <- parseUrl location
    return $ appendPath ".well-known/openid-configuration" req
  where
    appendPath suffix req =
        let p = path req
            p' = if "/" `isSuffixOf` p then p else p `append` "/"
        in
            req { path = p' `append` suffix }
