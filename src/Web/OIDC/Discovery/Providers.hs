{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery.Providers
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery.Providers
    ( google
    ) where

import Web.OIDC.Types (OP)

google :: OP
google = "https://accounts.google.com/.well-known/openid-configuration"

