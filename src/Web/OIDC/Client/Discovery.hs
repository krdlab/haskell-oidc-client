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
import           Data.Aeson                         (decode)
import           Data.ByteString                    (append)
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
        Just c  -> Provider c . jwks <$> getJwkSetJson (jwksUri c) `catch` rethrow
        Nothing -> throwM $ DiscoveryException "failed to decode configuration"
  where
    appendPath suffix req = req { path = path req `append` suffix }
    getConfiguration = do
        req <- parseUrl location
        let req' = appendPath "/.well-known/openid-configuration" req
        res <- httpLbs req' manager
        return $ decode $ responseBody res
    getJwkSetJson url = do
        req <- parseUrl url
        res <- httpLbs req manager
        return $ responseBody res
    jwks j = maybe single Jwk.keys (decode j)
      where
        single = case decode j of
                     Just k  -> return k
                     Nothing -> mempty
