{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Client.Discovery.Issuers
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Client.Discovery.Issuers
    ( google
    ) where

import Web.OIDC.Client.Types (IssuerLocation)

google :: IssuerLocation
google = "https://accounts.google.com"
