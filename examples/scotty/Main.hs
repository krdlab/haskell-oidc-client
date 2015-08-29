{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Control.Applicative ((<$>))
import Control.Monad.IO.Class (liftIO)
import Crypto.Random.AESCtr (makeSystem)
import Crypto.Random.API (CPRG, cprgGenBytes)
import Data.ByteString.Base32 (encode)
import Data.Default (def)
import Data.IORef (IORef, newIORef, atomicModifyIORef', readIORef)
import Data.Map (Map)
import qualified Data.Map as M
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8)
import Data.Text.Lazy (pack)
import Data.Tuple (swap)
import Network.HTTP.Types (badRequest400)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Text.Blaze.Html.Renderer.Text (renderHtml)
import Text.Blaze.Html5 ((!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Web.OIDC.Client (OIDC(..), State, Code, OpenIdConfiguration(..))
import qualified Web.OIDC.Client as OIDC
import Web.Scotty (scotty, middleware, get, param, post, redirect, html, status, text)
import Web.Scotty.Cookie (setSimpleCookie, getCookie)

type SessionStateMap = Map Text State

main :: IO ()
main = do
    op <- OIDC.discover OIDC.google
    let oidc = def {
          oidcAuthorizationSeverUrl = authorizationEndpoint op
        , oidcTokenEndpoint         = tokenEndpoint op
        , oidcClientId              = "your client id"
        , oidcClientSecret          = "your client secret"
        , oidcRedirectUri           = "http://localhost:3000/callback"
        }
    cprg <- makeSystem >>= newIORef
    ssm  <- newIORef M.empty
    run oidc cprg ssm

run :: CPRG g => OIDC -> IORef g -> IORef SessionStateMap -> IO ()
run oidc cprg ssm = scotty 3000 $ do
    middleware logStdoutDev

    get "/login" $
        blaze $ do
            H.h1 "Login"
            H.form ! A.method "post" ! A.action "/login" $
                H.button ! A.type_ "submit" $ "login"

    post "/login" $ do
        state <- genState
        loc <- liftIO $
            OIDC.getAuthenticationRequestUrl
                oidc
                [OIDC.Email]
                (Just state)
                []
        sid <- genSessionId
        saveState sid state
        setSimpleCookie "test-session" sid
        redirect $ pack . show $ loc

    get "/callback" $ do
        code :: Code   <- param "code"
        state :: State <- param "state"
        cookie <- getCookie "test-session"
        case cookie of
            Nothing  -> status401
            Just sid -> do
                sst <- getStateBy sid
                if state == sst
                    then do
                        tokens <- liftIO $ OIDC.requestTokens oidc code
                        -- TODO: validation
                        let claims = OIDC.getClaims $ OIDC.idToken tokens
                        blaze $ do
                            H.h1 "Result"
                            H.pre $ H.toHtml $ show claims
                    else status401

  where
    blaze = html . renderHtml
    status401 = status badRequest400 >> text "cookie not found"

    gen              = encode <$> atomicModifyIORef' cprg (swap . cprgGenBytes 64)
    genSessionId     = liftIO $ decodeUtf8 <$> gen
    genState         = liftIO gen
    saveState sid st = liftIO $ atomicModifyIORef' ssm $ \m -> (M.insert sid st m, ())
    getStateBy sid   = liftIO $ do
        m <- readIORef ssm
        case M.lookup sid m of
            Just st -> return st
            Nothing -> return ""

