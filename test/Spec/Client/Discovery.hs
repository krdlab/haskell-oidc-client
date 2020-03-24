{-# OPTIONS_GHC -Wno-warnings-deprecations #-}
{-# LANGUAGE OverloadedStrings #-}
module Spec.Client.Discovery where

import           Network.HTTP.Client       (path)
import           Test.Hspec                (Spec, describe, it, shouldBe)
import           Web.OIDC.Client.Discovery (generateDiscoveryUrl)


tests :: Spec
tests =
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
