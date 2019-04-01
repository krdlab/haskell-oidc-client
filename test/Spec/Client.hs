{-# LANGUAGE OverloadedStrings #-}
module Spec.Client where

import           Data.ByteString         (ByteString)
import           Data.Text               (unpack)
import           Data.Text.Encoding      (decodeUtf8)
import           Network.HTTP.Client     (newManager)
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.HTTP.Types      (urlEncode)
import           Test.Hspec              (Spec, describe, it, shouldContain,
                                          shouldNotContain, shouldThrow)
import           Web.OIDC.Client

clientId, clientSecret, redirectUri, nonce :: ByteString
clientId = "dummy client id"
clientSecret = "dummy client secret"
redirectUri = "http://localhost"
nonce = "dummy nonce"

tests :: Spec
tests = do
    describe "CodeFlow.getAuthenticationRequestUrl" $ do

        it "should return a url that has required parameters" $ do
            manager  <- newManager tlsManagerSettings
            provider <- discover google manager
            let oidc = setCredentials clientId clientSecret redirectUri $ newOIDC provider
            url <- getAuthenticationRequestUrl oidc [] Nothing []
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
            url <- getAuthenticationRequestUrl oidc [email] (Just state) [("nonce", Just nonce)]
            show url `shouldContain` (toES "scope" ++ "=" ++ toES "openid email")
            show url `shouldContain` (toES "state" ++ "=" ++ toES state)
            show url `shouldContain` (toES "nonce" ++ "=" ++ toES nonce)

    describe "CodeFlow.validateClaims" $ do
        it "should succeed at a validation of correct claims" $ do
            let issuer' = "http://localhost"
                clientId' = decodeUtf8 clientId
            now <- getCurrentIntDate
            let claims' = defClaims { jwtIss = Just issuer'
                                    , jwtAud = Just [clientId']
                                    , jwtExp = Just (add 10 now)
                                    }
            validateClaims issuer' clientId' now claims'
            validateClaims issuer' clientId' now (claims' { jwtAud = Just ["other id", clientId'] })

        it "should throw ValidationException if 'iss' field is invalid" $ do
            let issuer' = "http://localhost"
                clientId' = decodeUtf8 clientId
            now <- getCurrentIntDate
            let claims' = defClaims { jwtIss = Just "http://localhost/hoge"
                                    , jwtAud = Just [clientId']
                                    , jwtExp = Just (add 10 now)
                                    }
            validateClaims issuer' clientId' now claims'
                `shouldThrow` isValidationException

        it "should throw ValidationException if 'aud' field does not contain Client ID" $ do
            let issuer' = "http://localhost"
                clientId' = decodeUtf8 clientId
            now <- getCurrentIntDate
            let claims' = defClaims { jwtIss = Just issuer'
                                    , jwtAud = Just ["other id"]
                                    , jwtExp = Just (add 10 now)
                                    }
            validateClaims issuer' clientId' now claims'
                `shouldThrow` isValidationException

        it "should throw ValidationException if 'exp' field expired" $ do
            let issuer' = "http://localhost"
                clientId' = decodeUtf8 clientId
            now <- getCurrentIntDate
            let claims' = defClaims { jwtIss = Just issuer'
                                    , jwtAud = Just [clientId']
                                    , jwtExp = Just (add (-1) now)
                                    }
            validateClaims issuer' clientId' now claims'
                `shouldThrow` isValidationException

  where
    toES = unpack . decodeUtf8 . urlEncode True
    defClaims = JwtClaims { jwtIss = Nothing
                          , jwtSub = Nothing
                          , jwtAud = Nothing
                          , jwtExp = Nothing
                          , jwtNbf = Nothing
                          , jwtIat = Nothing
                          , jwtJti = Nothing
                          }
    add sec (IntDate t) = IntDate $ t + sec
    isValidationException e = case e of
        (ValidationException _) -> True
        _                       -> False
