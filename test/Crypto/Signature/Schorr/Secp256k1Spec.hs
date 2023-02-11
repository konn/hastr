{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Crypto.Signature.Schorr.Secp256k1Spec (test_bytesNatural) where

import Crypto.Signature.Schorr.Secp256k1
import qualified Data.ByteString as BS
import Data.Maybe (fromJust)
import GHC.Generics
import Numeric.Natural (Natural)
import Test.Tasty
import Test.Tasty.QuickCheck

newtype Fp = Fp {runFp :: Natural}
  deriving (Show, Eq, Ord, Generic)

instance Arbitrary Fp where
  arbitrary = Fp . (`rem` kp) . fromInteger . getNonNegative <$> arbitrary

kp :: Natural
kp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

instance Arbitrary Bytes32 where
  arbitrary = fromJust . fromByteString . BS.pack <$> vector 32

test_bytesNatural :: TestTree
test_bytesNatural =
  testGroup
    "Bytes32 <-> Natural conversion"
    [ testProperty "fromBytes32 . toBytes32 == id" $ \(Fp n) ->
        bytes32ToNatural (naturalToBytes32 n) === n
    , testProperty "toBytes32 . fromBytes32 == id" $ \b32 ->
        naturalToBytes32 (bytes32ToNatural b32) == b32
    ]
