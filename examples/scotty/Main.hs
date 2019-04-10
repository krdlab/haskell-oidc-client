{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Main where

import           Control.Monad.IO.Class               (liftIO)
import           Control.Monad.Reader                 (ReaderT, ask, lift,
                                                       runReaderT)
import           Crypto.Random.AESCtr                 (AESRNG, makeSystem)
import           Crypto.Random.API                    (cprgGenBytes)
import           Data.Aeson (FromJSON)
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
import           GHC.Generics (Generic)
import           Network.HTTP.Client                  (Manager, newManager)
import           Network.HTTP.Client.TLS              (tlsManagerSettings)
import           Network.HTTP.Types                   (badRequest400,
                                                       unauthorized401)
import           Network.Wai.Middleware.RequestLogger (logStdoutDev)
import           System.Environment                   (getEnv)
import           Text.Blaze.Html                      (Html)
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

type SessionStateMap = Map T.Text (O.State, O.Nonce)

data AuthServerEnv = AuthServerEnv
    { oidc :: O.OIDC
    , cprg :: IORef AESRNG
    , ssm  :: IORef SessionStateMap
    , mgr  :: Manager
    }

type AuthServer a = ScottyT TL.Text (ReaderT AuthServerEnv IO) a

newtype ProfileClaims = ProfileClaims
    { email :: T.Text
    } deriving (Show, Generic)

instance FromJSON ProfileClaims

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
                    in fst <$> B.readInt p

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

        sid <- genSessionId cprg
        let store = sessionStoreFromSession cprg ssm sid
        loc <- liftIO $ O.prepareAuthenticationRequestUrl store oidc [O.email] []
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
                let store = sessionStoreFromSession cprg ssm sid
                state <- param "state"
                code  <- param "code"
                tokens <- liftIO $ O.getValidTokens store oidc mgr state code
                blaze $ htmlResult tokens
            Nothing  -> status400 "cookie not found"

    htmlResult :: O.Tokens ProfileClaims -> Html
    htmlResult tokens = do
        H.h1 "Result"
        H.pre . H.toHtml . show $ tokens
    gen cprg                   = encode <$> atomicModifyIORef' cprg (swap . cprgGenBytes 64)
    genSessionId cprg          = liftIO $ decodeUtf8 <$> gen cprg
    genBytes cprg              = liftIO $ gen cprg
    saveState ssm sid st nonce = liftIO $ atomicModifyIORef' ssm $ \m -> (M.insert sid (st, nonce) m, ())
    getStateBy ssm sid         = liftIO $ do
        m <- M.lookup sid <$> readIORef ssm
        return $ case m of
            Just (st, nonce) -> (Just st, Just nonce)
            _                -> (Nothing, Nothing)
    deleteState ssm sid  = liftIO $ atomicModifyIORef' ssm $ \m -> (M.delete sid m, ())

    sessionStoreFromSession cprg ssm sid =
        O.SessionStore
            { sessionStoreGenerate = genBytes cprg
            , sessionStoreSave     = saveState ssm sid
            , sessionStoreGet      = getStateBy ssm sid
            , sessionStoreDelete   = deleteState ssm sid
            }

    blaze = html . renderHtml
    param' n = (Just <$> param n) `rescue` (\_ -> return Nothing)
    status400 m = status badRequest400   >> text m
    status401 m = status unauthorized401 >> text m
