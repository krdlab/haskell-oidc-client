{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery where

import Data.Aeson (decode)
import Data.Maybe (fromJust)
import Network.HTTP.Client (Manager, parseUrl, httpLbs, responseBody)
import Web.OIDC.Types

discover :: OP -> Manager -> IO OpenIdConfiguration
discover uri manager = do
    req <- parseUrl uri
    res <- httpLbs req manager
    return $ fromJust . decode $ responseBody res
