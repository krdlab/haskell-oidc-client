{-# OPTIONS_GHC -Wno-warnings-deprecations #-}
{-# LANGUAGE OverloadedStrings #-}
module Spec.Client.Discovery where

import           Data.Maybe                         (isJust)
import           Network.HTTP.Client                (newManager, path)
import           Network.HTTP.Client.TLS            (tlsManagerSettings)
import           Test.Hspec                         (Spec, describe, it,
                                                     shouldBe, shouldSatisfy)
import           Web.OIDC.Client.Discovery.Provider (Provider(..))
import           Web.OIDC.Client.Discovery          (generateDiscoveryUrl,
                                                     discover, google)


tests :: Spec
tests = do
    describe "Discovery.generateDiscoveryUrl" $ do
        it "should return a valid URL" $ do
            url <- generateDiscoveryUrl "https://accounts.google.com"
            path url `shouldBe` "/.well-known/openid-configuration"

        it "should return a valid URL if the location has a trailing slash" $ do
            url <- generateDiscoveryUrl "https://accounts.google.com/"
            path url `shouldBe` "/.well-known/openid-configuration"

        it "should return a valid URL if the location has a path" $ do
            url <- generateDiscoveryUrl "https://login.microsoftonline.com/common/v2.0"
            path url `shouldBe` "/common/v2.0/.well-known/openid-configuration"

        it "should return a valid URL if the location has both path and trailing slash" $ do
            url <- generateDiscoveryUrl "https://login.microsoftonline.com/common/v2.0/"
            path url `shouldBe` "/common/v2.0/.well-known/openid-configuration"

    describe "Discovery.discover" $ do
        -- This test requires an active internet connection (and Google
        -- continuing to provide this service).
        it "should pick up an expiration time from Google" $ do
            manager  <- newManager tlsManagerSettings
            Provider{ validUntil = v } <- discover google manager
            v `shouldSatisfy` isJust
