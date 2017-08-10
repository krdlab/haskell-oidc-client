import Test.Hspec (hspec)
import qualified Spec.Client as Client
import qualified Spec.Client.Internal as Internal

main :: IO ()
main = hspec $ do
    Client.tests
    Internal.tests
