{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Control.Monad.IO.Class               (liftIO)
import           Control.Monad.Reader                 (ReaderT, ask, lift,
                                                       runReaderT)
import           Crypto.Random.AESCtr                 (AESRNG, makeSystem)
import           Crypto.Random.API                    (cprgGenBytes)
import           Data.ByteString                      (ByteString)
import           Data.ByteString.Base64.URL           (encode)
import qualified Data.ByteString.Char8                as B
import           Data.IORef                           (IORef,
                                                       atomicModifyIORef',
                                                       newIORef, readIORef)
import           Data.List                            as L
import           Data.Map                             (Map)
import qualified Data.Map                             as M
import           Data.Maybe                           (Maybe (..), fromMaybe)
import           Data.Monoid                          ((<>))
import           Data.Text                            as T
import           Data.Text.Encoding                   (decodeUtf8)
import           Data.Text.Lazy                       as TL
import           Data.Tuple                           (swap)
import           Network.HTTP.Client                  (Manager, newManager)
import           Network.HTTP.Client.TLS              (tlsManagerSettings)
import           Network.HTTP.Types                   (badRequest400,
                                                       unauthorized401)
import           Network.Wai.Middleware.RequestLogger (logStdoutDev)
import           System.Environment                   (getEnv)
import           Text.Blaze.Html.Renderer.Text        (renderHtml)
import           Text.Blaze.Html5                     ((!))
import qualified Text.Blaze.Html5                     as H
import qualified Text.Blaze.Html5.Attributes          as A
import qualified Web.OIDC.Client                      as O
import           Web.Scotty.Cookie                    (getCookie,
                                                       setSimpleCookie)
import           Web.Scotty.Trans                     (ScottyT, get, html,
                                                       middleware, param, post,
                                                       redirect, rescue,
                                                       scottyT, status, text)

type SessionStateMap = Map T.Text O.State

data AuthServerEnv = AuthServerEnv
    { oidc :: O.OIDC
    , cprg :: IORef AESRNG
    , ssm  :: IORef SessionStateMap
    , mgr  :: Manager
    }

type AuthServer a = ScottyT TL.Text (ReaderT AuthServerEnv IO) a

main :: IO ()
main = do
    baseUrl      <- B.pack <$> getEnv "OPENID_CLIENT_BASE_URL"
    clientId     <- B.pack <$> getEnv "OPENID_CLIENT_ID"
    clientSecret <- B.pack <$> getEnv "OPENID_CLIENT_SECRET"

    let port = getPort baseUrl
        redirectUri = baseUrl <> "/login/cb"

    cprg <- makeSystem >>= newIORef
    ssm  <- newIORef M.empty
    mgr  <- newManager tlsManagerSettings
    prov <- O.discover "https://accounts.google.com" mgr
    let oidc = O.setCredentials clientId clientSecret redirectUri $ O.newOIDC prov

    run port oidc cprg ssm mgr

getPort :: ByteString -> Int
getPort bs = fromMaybe 3000 port
  where
    port = case B.split ':' bs of
        []  -> Nothing
        [_] -> Nothing
        xs  -> let p = (!! 0) . L.reverse $ xs
                    in B.readInt p >>= return . fst

run :: Int -> O.OIDC -> IORef AESRNG -> IORef SessionStateMap -> Manager -> IO ()
run port oidc cprg ssm mgr = scottyT port runReader run'
  where
    runReader a = runReaderT a (AuthServerEnv oidc cprg ssm mgr)

run' :: AuthServer ()
run' = do
    middleware logStdoutDev

    get "/login" $
        blaze htmlLogin

    post "/login" $ do
        AuthServerEnv{..} <- lift ask
        state <- genState cprg
        loc   <- liftIO $ O.getAuthenticationRequestUrl oidc [O.email] (Just state) []
        sid   <- genSessionId cprg
        saveState ssm sid state
        setSimpleCookie cookieName sid
        redirect . TL.pack . show $ loc

    get "/login/cb" $ do
        err <- param' "error"
        case err of
            Just e  -> status401 e
            Nothing -> getCookie cookieName >>= doCallback

  where
    cookieName = "test-session"

    htmlLogin = do
        H.h1 "Login"
        H.form ! A.method "post" ! A.action "/login" $
            H.button ! A.type_ "submit" $ "login"

    doCallback cookie =
        case cookie of
            Just sid -> do
                AuthServerEnv{..} <- lift ask
                state <- param "state"
                sst   <- getStateBy ssm sid
                if state == sst
                    then do
                        code   <- param "code"
                        tokens <- liftIO $ O.requestTokens oidc code mgr
                        blaze $ htmlResult tokens
                    else status400 "state not match"
            Nothing  -> status400 "cookie not found"

    htmlResult tokens = do
        H.h1 "Result"
        H.pre . H.toHtml . show . O.claims . O.idToken $ tokens

    gen cprg             = encode <$> atomicModifyIORef' cprg (swap . cprgGenBytes 64)
    genSessionId cprg    = liftIO $ decodeUtf8 <$> gen cprg
    genState cprg        = liftIO $ gen cprg
    saveState ssm sid st = liftIO $ atomicModifyIORef' ssm $ \m -> (M.insert sid st m, ())
    getStateBy ssm sid   = liftIO $ do
        m <- readIORef ssm
        case M.lookup sid m of
            Just st -> return st
            Nothing -> return ""

    blaze = html . renderHtml
    param' n = (Just <$> param n) `rescue` (\_ -> return Nothing)
    status400 m = status badRequest400   >> text m
    status401 m = status unauthorized401 >> text m
