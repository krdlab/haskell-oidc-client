{-|
    Module: Web.OIDC.Client.Tokens
    Maintainer: krdlab@gmail.com
    Stability: experimental
-}
module Web.OIDC.Client.Tokens
    (
      Tokens(..)
    , IdToken(..)
    , IdTokenClaims(..)
    , decodePublicClaims
    , rawPublicClaims
    ) where

import Control.Monad ((>=>))
import Data.Aeson (FromJSON, decodeStrict')
import Data.ByteString (ByteString)
import Data.Text (Text)
import Jose.Jwt (IntDate, Jwt, JwtContent)
import Jose.Jwt as Jwt
import Prelude hiding (exp)

data Tokens = Tokens
    { accessToken  :: Text
    , tokenType    :: Text
    , idToken      :: IdToken
    , expiresIn    :: Maybe Integer
    , refreshToken :: Maybe Text
    }
  deriving (Show, Eq)

data IdToken = IdToken
    { claims          :: IdTokenClaims
    , jwt             :: !Jwt
    , jwtContent      :: !JwtContent
    }
  deriving (Show, Eq)


-- | tries to decode the 'rawPublicClaims' of a 'IdToken' into a user provided `FromJSON` instance
decodePublicClaims :: FromJSON a => IdToken -> Maybe a
decodePublicClaims = rawPublicClaims >=> decodeStrict'


-- | returns the 'ByteString' with the payload in case of an signed or encrypted JWT
-- | 'Nothing' in case of an unsecured JWT
rawPublicClaims :: IdToken -> Maybe ByteString
rawPublicClaims = go . jwtContent
  where go (Jwt.Unsecured _)   = Nothing
        go (Jwt.Jws (_, raw))  = Just raw
        go (Jwt.Jwe (_, raw))  = Just raw


data IdTokenClaims = IdTokenClaims
    { iss :: Text
    , sub :: Text
    , aud :: [Text]
    , exp :: IntDate
    , iat :: IntDate
    -- TODO: optional
    }
  deriving (Show, Eq)
