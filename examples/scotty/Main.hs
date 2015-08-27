{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad.IO.Class (liftIO)
import Data.Default (def)
import Data.Text.Lazy (pack)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Text.Blaze.Html.Renderer.Text (renderHtml)
import Text.Blaze.Html5 ((!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Web.OIDC.Client (OIDC(..))
import qualified Web.OIDC.Client as OIDC
import Web.Scotty (scotty, middleware, get, param, post, redirect, html)

oidc :: OIDC
oidc = def
    { oidcAuthorizationSeverUrl = "https://accounts.google.com/o/oauth2/auth"
    , oidcTokenEndpoint = "https://www.googleapis.com/oauth2/v3/token"
    , oidcClientId = "your client id"
    , oidcClientSecret = "your client secret"
    , oidcRedirectUri = "http://localhost:3000/callback"
    }

main :: IO ()
main = scotty 3000 $ do
    middleware logStdoutDev

    get "/login" $
        blaze $ do
            H.h1 "Login"
            H.form ! A.method "post" ! A.action "/login" $
                H.button ! A.type_ "submit" $ "login"

    post "/login" $ do
        loc <- liftIO $
            OIDC.getAuthenticationRequestUrl
                oidc
                [OIDC.Email]
                []  -- TODO: state
        redirect $ pack . show $ loc

    get "/callback" $ do
        code <- param "code"
        -- TODO: state <- param "state"
        tokens <- liftIO $ OIDC.requestTokens oidc code
        -- TODO: validation
        let claims = OIDC.getClaims $ OIDC.idToken tokens
        blaze $ do
            H.h1 "Result"
            H.pre $ H.toHtml $ show claims

  where
    blaze = html . renderHtml

