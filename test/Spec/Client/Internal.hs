{-# LANGUAGE OverloadedStrings #-}
module Spec.Client.Internal where

import           Data.Aeson               (decode)
import           Jose.Jwt                 (Jwt (..))
import           Test.Hspec               (Spec, describe, it, shouldBe)
import qualified Web.OIDC.Client.Internal as I

tests :: Spec
tests =
    describe "Internal: Decode TokensResponse JSON data" $ do
        it "should be successful decoding a JSON data which has full fields" $ do
            let json = "{\"access_token\":\"access token\",\"token_type\":\"token type\",\"id_token\":\"dummy jwt\",\"expires_in\":123,\"refresh_token\":\"refresh token\"}"
            decode json `shouldBe` Just (I.TokensResponse "access token" "token type" (Jwt "dummy jwt") (Just 123) (Just "refresh token"))

        it "should be successful decoding a JSON data without 'refresh_token' field" $ do
            let json = "{\"access_token\":\"access token\",\"token_type\":\"token type\",\"id_token\":\"dummy jwt\",\"expires_in\":123}"
            decode json `shouldBe` Just (I.TokensResponse "access token" "token type" (Jwt "dummy jwt") (Just 123) Nothing)

        it "should be successful decoding a JSON data without 'expires_in' and 'refresh_token' fields" $ do
            let json = "{\"access_token\":\"access token\",\"token_type\":\"token type\",\"id_token\":\"dummy jwt\"}"
            decode json `shouldBe` Just (I.TokensResponse "access token" "token type" (Jwt "dummy jwt") Nothing Nothing)

        it "should be failure decoding a JSON data from the lack of a required field" $ do
            let json = "{\"access_token\":\"access token\",\"token_type\":\"token type\"}"
            decode json `shouldBe` (Nothing :: Maybe I.TokensResponse)

        -- NOTE: The 'expires_in' field is an integer, is not included a fractional part. But, I received the report https://github.com/krdlab/haskell-oidc-client/pull/15.
        -- see also: https://tools.ietf.org/html/rfc6749#appendix-A.14
        it "should be successful decoding a JSON data with 'expires_in' field which has a fractional part" $ do
            let json = "{\"access_token\":\"access token\",\"token_type\":\"token type\",\"id_token\":\"dummy jwt\",\"expires_in\":123.45}"
            decode json `shouldBe` Just (I.TokensResponse "access token" "token type" (Jwt "dummy jwt") (Just 123) Nothing)
