{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-|
Module: Web.OIDC.Types
Maintainer: krdlab@gmail.com
Stability: experimental
-}
module Web.OIDC.Types
    ( OP
    , Scope
    , ScopeValue(..)
    , State
    , Parameter
    , RequestParameters
    , Code
    , OpenIdConfiguration(..)
    , OIDC(..)
    , setProviderConf
    , setCredentials
    , Tokens(..)
    , IdToken(..)
    , IdTokenClaims(..)
    , toIdTokenClaims
    , newOIDC
    , OpenIdException(..)
    ) where

import Control.Applicative ((<$>), (<*>), (<*), (*>), (<|>))
import Control.Exception (Exception)
import Control.Monad (mzero)
import Crypto.Random.API (CPRG)
import Data.Aeson (FromJSON, parseJSON, Value(..), (.:), withText)
import Data.Attoparsec.Text (parseOnly, endOfInput, string)
import Data.ByteString (ByteString)
import Data.IORef (IORef)
import Data.Maybe (fromJust)
import Data.Text (unpack)
import Data.Typeable (Typeable)
import Jose.Jwt (Jwt, JwtClaims(..), JwtError, IntDate)

type OP = String

data ScopeValue =
      OpenId
    | Profile
    | Email
    | Address
    | Phone
    | OfflineAccess
    deriving (Show, Eq)

instance FromJSON ScopeValue where
    parseJSON = withText "ScopeValue" (run parser)
      where
        run p t =
            case parseOnly (p <* endOfInput) t of
                Right r   -> return r
                Left  err -> fail $ "could not parse scope value: " ++ err
        parser =    string "openid" *> return OpenId
                <|> string "profile" *> return Profile
                <|> string "email" *> return Email
                <|> string "address" *> return Address
                <|> string "phone" *> return Phone
                <|> string "offline_access" *> return OfflineAccess

type Scope = [ScopeValue]

type State = ByteString

type Parameter = ByteString

type RequestParameters = [(Parameter, Maybe ByteString)]

type Code = ByteString

data OpenIdConfiguration = OpenIdConfiguration
    { issuer                            :: String
    , authorizationEndpoint             :: String
    , tokenEndpoint                     :: String
    , userinfoEndpoint                  :: String
    , revocationEndpoint                :: String
    , jwksUri                           :: String
    , responseTypesSupported            :: [String]
    , subjectTypesSupported             :: [String]
    , idTokenSigningAlgValuesSupported  :: [String]
    , scopesSupported                   :: [String]  -- TODO: Scope
    , tokenEndpointAuthMethodsSupported :: [String]
    , claimsSupported                   :: [String]
    }
  deriving (Show, Eq)

instance FromJSON OpenIdConfiguration where
    parseJSON (Object o) = OpenIdConfiguration
        <$> o .: "issuer"
        <*> o .: "authorization_endpoint"
        <*> o .: "token_endpoint"
        <*> o .: "userinfo_endpoint"
        <*> o .: "revocation_endpoint"
        <*> o .: "jwks_uri"
        <*> o .: "response_types_supported"
        <*> o .: "subject_types_supported"
        <*> o .: "id_token_signing_alg_values_supported"
        <*> o .: "scopes_supported"
        <*> o .: "token_endpoint_auth_methods_supported"
        <*> o .: "claims_supported"
    parseJSON _ = mzero

data (CPRG g) => OIDC g = OIDC
    { oidcAuthorizationSeverUrl :: String
    , oidcTokenEndpoint :: String
    , oidcClientId :: ByteString
    , oidcClientSecret :: ByteString
    , oidcRedirectUri :: ByteString
    , oidcProviderConf :: OpenIdConfiguration
    , oidcCPRGRef :: Maybe (IORef g)
    }

newOIDC :: CPRG g => Maybe (IORef g) -> OIDC g
newOIDC ref = OIDC
    { oidcAuthorizationSeverUrl = error "You must specify oidcAuthorizationSeverUrl"
    , oidcTokenEndpoint = error "You must specify oidcTokenEndpoint"
    , oidcClientId = error "You must specify oidcClientId"
    , oidcClientSecret = error "You must specify oidcClientSecret"
    , oidcRedirectUri = error "You must specify oidcRedirectUri"
    , oidcProviderConf = error "You must specify oidcProviderConf"
    , oidcCPRGRef = ref
    }

setProviderConf :: CPRG g => OpenIdConfiguration -> OIDC g -> OIDC g
setProviderConf c oidc =
    oidc { oidcAuthorizationSeverUrl = authorizationEndpoint c
         , oidcTokenEndpoint = tokenEndpoint c
         , oidcProviderConf = c
         }

setCredentials :: CPRG g => ByteString -> ByteString -> ByteString -> OIDC g -> OIDC g
setCredentials cid secret redirect oidc =
    oidc { oidcClientId = cid
         , oidcClientSecret = secret
         , oidcRedirectUri = redirect
         }

data Tokens = Tokens
    { accessToken :: String
    , tokenType :: String
    , idToken :: IdToken
    , expiresIn :: Maybe Integer
    , refreshToken :: Maybe String
    }
  deriving (Show, Eq)

data IdToken = IdToken
    { itClaims :: IdTokenClaims
    , itJwt :: Jwt
    }
  deriving (Show, Eq)

data IdTokenClaims = IdTokenClaims
    { itcIss :: String
    , itcSub :: String
    , itcAud :: [String]
    , itcExp :: IntDate
    , itcIat :: IntDate
    -- TODO: optional
    }
  deriving (Show, Eq)

toIdTokenClaims :: JwtClaims -> IdTokenClaims
toIdTokenClaims c = IdTokenClaims
    { itcIss =     unpack $ fromJust (jwtIss c)
    , itcSub =     unpack $ fromJust (jwtSub c)
    , itcAud = map unpack $ fromJust (jwtAud c)
    , itcExp =              fromJust (jwtExp c)
    , itcIat =              fromJust (jwtIat c)
    }

data OpenIdException =
      JwtExceptoin JwtError
    | ValidationException String
  deriving (Show, Typeable)

instance Exception OpenIdException

