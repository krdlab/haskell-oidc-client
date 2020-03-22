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
    ) where

import           Control.Monad.Catch                (catch, throwM)
import           Data.Aeson                         (eitherDecode)
import           Data.ByteString                    (append)
import           Data.Text                          (pack)
import qualified Jose.Jwk                           as Jwk
import           Network.HTTP.Client                (Manager, httpLbs, path,
                                                     responseBody)

import           Web.OIDC.Client.Discovery.Issuers  (google)
import           Web.OIDC.Client.Discovery.Provider (Configuration (..),
                                                     Provider (..))
import           Web.OIDC.Client.Internal           (parseUrl, rethrow)
import           Web.OIDC.Client.Types              (IssuerLocation,
                                                     OpenIdException (..))

-- | This function obtains OpenID Provider configuration and JWK set.
discover
    :: IssuerLocation   -- ^ OpenID Provider's Issuer location
    -> Manager
    -> IO Provider
discover location manager = do
    conf <- getConfiguration `catch` rethrow
    case conf of
        Right c   -> do
            json <- getJwkSetJson (jwksUri c) `catch` rethrow
            case jwks json of
                Right keys -> return $ Provider c keys
                Left  err  -> throwM $ DiscoveryException ("Failed to decode JwkSet: " <> pack err)
        Left  err -> throwM $ DiscoveryException ("Failed to decode configuration: " <> pack err)
  where
    appendPath suffix req = req { path = path req `append` suffix }

    getConfiguration = do
        req <- parseUrl location
        let req' = appendPath ".well-known/openid-configuration" req
        res <- httpLbs req' manager
        return $ eitherDecode $ responseBody res

    getJwkSetJson url = do
        req <- parseUrl url
        res <- httpLbs req manager
        return $ responseBody res

    jwks j = Jwk.keys <$> eitherDecode j
