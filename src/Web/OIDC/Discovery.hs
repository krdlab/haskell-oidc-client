{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery where

import Data.Aeson (decode)
import Data.Maybe (fromJust)
import Network.HTTP.Client (newManager, parseUrl, httpLbs, responseBody)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Web.OIDC.Types

-- TODO: manager
discover :: OP -> IO OpenIdConfiguration
discover uri = do
    req <- parseUrl uri
    mgr <- newManager tlsManagerSettings
    res <- httpLbs req mgr
    return $ fromJust . decode $ responseBody res

