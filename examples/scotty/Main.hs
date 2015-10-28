{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Control.Applicative ((<$>))
import Control.Monad.IO.Class (liftIO)
import Crypto.Random.AESCtr (makeSystem)
import Crypto.Random.API (CPRG, cprgGenBytes)
import Data.ByteString (ByteString)
import Data.ByteString.Base32 (encode)
import qualified Data.ByteString.Char8 as B
import Data.IORef (IORef, newIORef, atomicModifyIORef', readIORef)
import Data.Map (Map)
import qualified Data.Map as M
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8)
import Data.Text.Lazy (pack)
import Data.Tuple (swap)
import Network.HTTP.Client (newManager, Manager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (badRequest400)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import System.Environment (getEnv)
import Text.Blaze.Html.Renderer.Text (renderHtml)
import Text.Blaze.Html5 ((!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import qualified Web.OIDC.Client as O
import qualified Web.OIDC.Client.Discovery as O
import Web.Scotty (scotty, middleware, get, param, post, redirect, html, status, text)
import Web.Scotty.Cookie (setSimpleCookie, getCookie)

type SessionStateMap = Map Text O.State

redirectUri :: ByteString
redirectUri  = "http://localhost:3000/callback"

main :: IO ()
main = do
    clientId     <- B.pack <$> getEnv "OPENID_CLIENT_ID"
    clientSecret <- B.pack <$> getEnv "OPENID_CLIENT_SECRET"

    cprg <- makeSystem >>= newIORef
    ssm  <- newIORef M.empty
    mgr  <- newManager tlsManagerSettings
    prov <- O.discover O.google mgr
    let oidc = O.setCredentials clientId clientSecret redirectUri $ O.setProvider prov $ O.newOIDC cprg

    run oidc cprg ssm mgr

run :: CPRG g => O.OIDC -> IORef g -> IORef SessionStateMap -> Manager -> IO ()
run oidc cprg ssm mgr = scotty 3000 $ do
    middleware logStdoutDev

    get "/login" $
        blaze $ do
            H.h1 "Login"
            H.form ! A.method "post" ! A.action "/login" $
                H.button ! A.type_ "submit" $ "login"

    post "/login" $ do
        state <- genState
        loc <- liftIO $ O.getAuthenticationRequestUrl oidc [O.Email] (Just state) []
        sid <- genSessionId
        saveState sid state
        setSimpleCookie "test-session" sid
        redirect $ pack . show $ loc

    get "/callback" $ do
        code  :: O.Code  <- param "code"
        state :: O.State <- param "state"
        cookie <- getCookie "test-session"
        case cookie of
            Nothing  -> status401
            Just sid -> do
                sst <- getStateBy sid
                if state == sst
                    then do
                        tokens <- liftIO $ O.requestTokens oidc code mgr
                        blaze $ do
                            H.h1 "Result"
                            H.pre . H.toHtml . show . O.claims . O.idToken $ tokens
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

