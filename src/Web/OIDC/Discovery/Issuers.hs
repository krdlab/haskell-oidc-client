{-# LANGUAGE OverloadedStrings #-}
{-|
Module: Web.OIDC.Discovery.Issuers
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Discovery.Issuers
    ( google
    ) where

import Web.OIDC.Types (IssuerLocation)

google :: IssuerLocation
google = "https://accounts.google.com"
