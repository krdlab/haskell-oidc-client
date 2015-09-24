{-# LANGUAGE OverloadedStrings #-}

import Test.Hspec

main :: IO ()
main = hspec $
    describe "dummy test" $
        it "dummy" $
            True `shouldBe` True
