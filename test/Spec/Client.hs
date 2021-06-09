{-# OPTIONS_GHC -Wno-warnings-deprecations #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BlockArguments #-}
module Spec.Client where

import           Data.Aeson              (Value (Null))
import           Data.ByteString         (ByteString)
import           Data.Text               (unpack)
import           Data.Text.Encoding      (decodeUtf8)
import           Network.HTTP.Client     (newManager)
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.HTTP.Types      (urlEncode)
import           Test.Hspec              (Spec, describe, it, shouldContain,
                                          shouldNotContain, shouldThrow)
import           Web.OIDC.Client
import           Control.Monad.Reader    (runReaderT)

import           Prelude                 hiding (exp)

clientId, clientSecret, redirectUri, nonce' :: ByteString
clientId = "dummy client id"
clientSecret = "dummy client secret"
redirectUri = "http://localhost"
nonce' = "dummy nonce"

tests :: Spec
tests = do
    describe "CodeFlow.getAuthenticationRequestUrl" $ do

        it "should return a url that has required parameters" $ do
            manager  <- newManager tlsManagerSettings
            provider <- discover google manager
            let oidc = setCredentials clientId clientSecret redirectUri $ newOIDC provider
            url <- runReaderT (getAuthenticationRequestUrl [] Nothing []) oidc
            show url `shouldContain` "response_type=code"
            show url `shouldContain` "scope=openid"
            show url `shouldContain` (toES "client_id" ++ "=" ++ toES clientId)
            show url `shouldContain` (toES "redirect_uri" ++ "=" ++ toES redirectUri)
            show url `shouldNotContain` toES clientSecret

        it "should return a url that has other parameters" $ do
            manager  <- newManager tlsManagerSettings
            provider <- discover google manager
            let oidc = setCredentials clientId clientSecret redirectUri $ newOIDC provider
                state = "dummy state"
            url <- runReaderT (getAuthenticationRequestUrl [email] (Just state) [("nonce", Just nonce')]) oidc
            show url `shouldContain` (toES "scope" ++ "=" ++ toES "openid email")
            show url `shouldContain` (toES "state" ++ "=" ++ toES state)
            show url `shouldContain` (toES "nonce" ++ "=" ++ toES nonce')

    describe "CodeFlow.validateClaims" $ do
        let issuer' = "http://localhost"
            clientId' = decodeUtf8 clientId
            createValidClaims now =
                IdTokenClaims
                    { iss = issuer'
                    , sub = "sub"
                    , aud = [clientId']
                    , exp = add 10 now
                    , iat = now
                    , nonce = Just nonce'
                    , otherClaims = Null
                    }
        it "should succeed at a validation of correct claims" $ do
            now <- getCurrentIntDate
            let claims' = createValidClaims now
            validateClaims issuer' clientId' now (Just nonce') claims'
            validateClaims issuer' clientId' now (Just nonce') claims' { aud = ["other id", clientId'] }

        it "should throw ValidationException if 'iss' field is invalid" $ do
            now <- getCurrentIntDate
            let claims' = createValidClaims now
            validateClaims issuer' clientId' now (Just nonce') claims' { iss = "http://localhost/hoge" }
                `shouldThrow` isValidationException

        it "should throw ValidationException if 'aud' field does not contain Client ID" $ do
            now <- getCurrentIntDate
            let claims' = createValidClaims now
            validateClaims issuer' clientId' now (Just nonce') claims' { aud = ["other id"] }
                `shouldThrow` isValidationException

        it "should throw ValidationException if 'exp' field expired" $ do
            now <- getCurrentIntDate
            let claims' = createValidClaims now
            validateClaims issuer' clientId' now (Just nonce') claims' { exp = add (-1) now }
                `shouldThrow` isValidationException

        it "should throw ValidationException if 'nonce' is not given" $ do
            now <- getCurrentIntDate
            let claims' = createValidClaims now
            validateClaims issuer' clientId' now (Just nonce') claims' { nonce = Nothing }
                `shouldThrow` isValidationException

        it "should throw ValidationException if 'nonce' is invalid" $ do
            now <- getCurrentIntDate
            let claims' = createValidClaims now
            validateClaims issuer' clientId' now (Just nonce') claims' { nonce = Just "other nonce" }
                `shouldThrow` isValidationException

  where
    toES = unpack . decodeUtf8 . urlEncode True
    add sec (IntDate t) = IntDate $ t + sec
    isValidationException e = case e of
        (ValidationException _) -> True
        _                       -> False
