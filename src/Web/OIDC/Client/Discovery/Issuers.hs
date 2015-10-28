{-# LANGUAGE OverloadedStrings #-}
{-|
    Module: Web.OIDC.Client.Discovery.Issuers
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Discovery.Issuers
    (
      google
    -- TODO: other services
    ) where

import Web.OIDC.Client.Types (IssuerLocation)

google :: IssuerLocation
google = "https://accounts.google.com"
