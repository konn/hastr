{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{- |
Schnorr sign for secp256k1 elliptic curve,
as specified in <https://bips.xyz/340 BIP-340>
-}
module Crypto.Signature.Schorr.Secp256k1 (
  Bytes32,
  bytes32ToNatural,
  naturalToBytes32,
  parseHexBytes32,
  Signature (..),
  parseSignature,
  fromSignature,
  randomBytes32,
  fromByteString,
  toByteString,
  fromSHA256,
  SecretKey (),
  rawSecretKey,
  generateSecretKey,
  toSecretKey,
  PublicKey (..),
  parseHexPublicKey,
  toPublicKey,
  Seed (..),
  randomSeed,
  sign,
  signM,
  verify,
  toLazyByteString,
  FromBytes32 (..),
) where

import Control.Arrow ((>>>))
import Control.Monad (guard, unless, when, (<$!>))
import Control.Monad.Loops (untilJust)
import Control.Monad.ST.Strict (runST)
import Crypto.RNG.Class (CryptoRNG (randomBytes))
import Data.Aeson
import Data.Bits (Bits (..), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.ByteString.Short (ShortByteString (..))
import qualified Data.ByteString.Short as SBS
import Data.Digest.Pure.SHA (Digest, SHA256State, bytestringDigest, sha256)
import Data.Function (on)
import Data.Hashable (Hashable)
import Data.Mod (Mod (..))
import Data.Monoid
import Data.Primitive.ByteArray (ByteArray (..))
import qualified Data.Primitive.ByteArray as BA
import Data.Proxy (Proxy (..))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT
import qualified Data.Text.Lazy.Encoding as LT
import qualified Data.Vector.Primitive as PV
import Data.Word (Word8)
import GHC.TypeNats (natVal)
import Numeric (readHex, showHex)
import Numeric.Natural

type P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

newtype Fp = Fp {unFp :: Mod P}
  deriving (Show, Eq, Ord)
  deriving newtype (Num, Fractional)

data Point
  = Fin {-# UNPACK #-} !Fp !Fp
  | Infinity
  deriving (Show, Eq, Ord)

newtype SecretKey = SecretKey {_rawSecretKey :: Bytes32}
  deriving (Show, Eq, Ord)
  deriving newtype (ToJSON, Hashable)

instance FromJSON SecretKey where
  parseJSON j =
    maybe (fail "Secret key out of range!") pure . toSecretKey =<< parseJSON j
  {-# INLINE parseJSON #-}

rawSecretKey :: SecretKey -> Bytes32
rawSecretKey = _rawSecretKey

toSecretKey :: Bytes32 -> Maybe SecretKey
{-# INLINE toSecretKey #-}
toSecretKey b =
  let !d = bytes32ToNatural b
   in if d == 0 || d >= order
        then Nothing
        else Just $ SecretKey b

parseHexPublicKey :: Text -> Either String PublicKey
{-# INLINE parseHexPublicKey #-}
parseHexPublicKey = fmap PublicKey . parseHexBytes32

newtype PublicKey = PublicKey {rawPublicKey :: Bytes32}
  deriving (Show, Eq, Ord)
  deriving newtype (FromJSON, ToJSON, Hashable)

newtype Seed = Seed {getSeed :: Bytes32}
  deriving (Show, Eq, Ord)
  deriving newtype (Hashable)

generateSecretKey :: CryptoRNG m => m SecretKey
{-# INLINE generateSecretKey #-}
generateSecretKey = untilJust $ toSecretKey <$!> randomBytes32

randomBytes32 :: CryptoRNG m => m Bytes32
{-# INLINE randomBytes32 #-}
randomBytes32 = Bytes32 . SBS.toShort <$> randomBytes 32

randomSeed :: CryptoRNG m => m Seed
randomSeed = Seed <$> randomBytes32

pointBytes32 :: Point -> Bytes32
pointBytes32 Infinity = error "Impossible happened!"
pointBytes32 (Fin x _) = naturalToBytes32 $ unMod $ unFp x

toPublicKey :: SecretKey -> PublicKey
{-# INLINE toPublicKey #-}
toPublicKey =
  PublicKey . pointBytes32 . (*. g) . bytes32ToNatural . _rawSecretKey

infixl 6 .+., .-.

(.-.) :: Point -> Point -> Point
l .-. r = l .+. negateP r

negateP :: Point -> Point
{-# INLINE negateP #-}
negateP = \case
  Infinity -> Infinity
  Fin x y -> Fin x (-y)

(.+.) :: Point -> Point -> Point
{-# INLINE (.+.) #-}
Infinity .+. q = q
p .+. Infinity = p
Fin x1 y1 .+. Fin x2 y2
  | x1 == x2, y1 == -y2 = Infinity
  | otherwise =
      let dx = x2 - x1
          dy = 2 * y1
          (!phi, !psi)
            | x1 == x2 = (3 * x1 * x1 / dy, (-3 * x1 * x1 * x1 + 2 * y1 * y1) / dy)
            | otherwise = ((y2 - y1) / dx, (y1 * x2 - y2 * x1) / dx)
          x' = phi * phi - x1 - x2
       in Fin x' (-phi * x' - psi)

infixr 7 *.

(*.) :: Natural -> Point -> Point
(*.) = go
  where
    go 0 _ = Infinity
    go 1 !p = p
    go !n !p =
      let (!q, !r) = n `quotRem` 2
          !hlf = go q p
       in if r == 1
            then hlf .+. hlf .+. p
            else hlf .+. hlf

newtype Bytes32 = Bytes32 {getBytes32 :: SBS.ShortByteString}
  deriving (Eq, Ord)
  deriving newtype (Hashable)

parseHexBytes32 :: Text -> Either String Bytes32
parseHexBytes32 txt = do
  let !len = T.length txt /= 64
  when len $
    Left $
      "Length must be 64, but got: " <> show len
  maybe (Left "Not a hex string!") (pure . naturalToBytes32) $
    readHexMaybe $
      T.unpack txt

instance ToJSON Bytes32 where
  toJSON = toJSON . show
  {-# INLINE toJSON #-}

instance FromJSON Bytes32 where
  parseJSON =
    withText "64-digit lower hex" $
      either fail pure . parseHexBytes32
  {-# INLINE parseJSON #-}

readHexMaybe :: String -> Maybe Natural
readHexMaybe str =
  case readHex str of
    [(p, "")] -> Just p
    _ -> Nothing

newtype ShowSM = ShowSM {getShowS :: ShowS}
  deriving (Semigroup, Monoid) via Endo String

instance Show Bytes32 where
  showsPrec _ =
    getShowS
      . PV.foldMap @_ @Word8
        ( \i ->
            let ds0 = showHex i ""
                ds = replicate (2 - length ds0) '0' <> ds0
             in ShowSM $ showString ds
        )
      . \case Bytes32 (SBS v) -> PV.Vector 0 32 (ByteArray v)
  {-# INLINE showsPrec #-}

fromByteString :: BS.ByteString -> Maybe Bytes32
{-# INLINE fromByteString #-}
fromByteString bs
  | BS.length bs == 32 = Just $ unsafeFromByteString bs
  | otherwise = Nothing

unsafeFromByteString :: BS.ByteString -> Bytes32
{-# INLINE unsafeFromByteString #-}
unsafeFromByteString = Bytes32 . SBS.toShort

toByteString :: Bytes32 -> BS.ByteString
{-# INLINE toByteString #-}
toByteString = SBS.fromShort . getBytes32

toLazyByteString :: Bytes32 -> LBS.ByteString
{-# INLINE toLazyByteString #-}
toLazyByteString = LBS.fromStrict . toByteString

fromSHA256 :: Digest SHA256State -> Bytes32
{-# INLINE fromSHA256 #-}
fromSHA256 = Bytes32 . SBS.toShort . LBS.toStrict . bytestringDigest

bytes32ToNatural :: Bytes32 -> Natural
{-# INLINE bytes32ToNatural #-}
bytes32ToNatural =
  SBS.foldl'
    (\l r -> (l `shiftL` 8) .|. fromIntegral @Word8 r)
    0
    . getBytes32

naturalToBytes32 :: Natural -> Bytes32
{-# INLINE naturalToBytes32 #-}
naturalToBytes32 =
  PV.unfoldrExactN
    32
    ( \i ->
        ( fromIntegral @_ @Word8 (i .&. 0xff)
        , i `shiftR` 8
        )
    )
    >>> PV.reverse
    >>> \case
      PV.Vector _ _ (ByteArray ba#) -> Bytes32 $ SBS ba#

order :: Natural
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

gx, gy :: Fp
gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

g :: Point
g = Fin gx gy

evenY :: Point -> Bool
evenY = \case
  Fin _ (Fp y) -> even $ unMod y
  _ -> False

hashTag :: LT.Text -> Bytes32 -> Bytes32
hashTag tag = hashTagLBS tag . LBS.fromStrict . toByteString

hashTagLBS :: LT.Text -> LBS.ByteString -> Bytes32
hashTagLBS tag msg =
  let hashedTag = bytestringDigest $ sha256 $ LT.encodeUtf8 tag
   in fromSHA256 $
        sha256 (hashedTag <> hashedTag <> msg)

signM :: CryptoRNG m => SecretKey -> Bytes32 -> m Signature
signM sk msg = untilJust $ do
  s <- randomSeed
  pure $ either (const Nothing) Just $ sign s sk msg

sign :: Seed -> SecretKey -> Bytes32 -> Either String Signature
sign a sk@(SecretKey skRaw) msg = do
  let (!d, !p) = toPointAndAdjust $ bytes32ToNatural skRaw
      pLBS = toLazyByteString (pointBytes32 p)
      msgLBS = toLazyByteString msg
      !t = zipWithBytes32 xor (naturalToBytes32 d) (hashTag "BIP0340/aux" $ getSeed a)
      !rand =
        hashTagLBS
          "BIP0340/nonce"
          (toLazyByteString t <> pLBS <> msgLBS)
      !k' = bytes32ToNatural rand `rem` order
  when (k' == 0) $
    Left $
      "Key k' degenerate: (k', rand, t) " <> show (k', rand, bytes32ToNatural rand, t)
  let (!k, !r) = toPointAndAdjust k'
      !e =
        bytes32ToNatural
          ( hashTagLBS "BIP0340/challenge" $
              toLazyByteString (pointBytes32 r) <> pLBS <> msgLBS
          )
          `rem` order
      !sig = Signature (pointBytes32 r) (naturalToBytes32 $ (k + e * d) `rem` order)
  unless (verify (toPublicKey sk) msg sig) $
    Left $
      "Verification failed for: "
        <> show (toPublicKey sk, msg, sig)
  pure sig

verify :: PublicKey -> Bytes32 -> Signature -> Bool
{-# INLINE verify #-}
verify (PublicKey pk) msg (Signature lh rh) =
  case liftX $ bytes32ToNatural pk of
    Nothing -> False
    Just !p ->
      let !r = bytes32ToNatural lh
          s = bytes32ToNatural rh
          e =
            bytes32ToNatural
              ( hashTagLBS "BIP0340/challenge" $
                  toLazyByteString lh
                    <> toLazyByteString (pointBytes32 p)
                    <> toLazyByteString msg
              )
              `rem` order
          rPt = s *. g .-. e *. p
       in r < kp && s < order && isFinite rPt && evenY rPt && xOf rPt == r

xOf :: Point -> Natural
xOf = \case
  Infinity -> error "Impossible"
  Fin x _ -> unMod $ unFp x

isFinite :: Point -> Bool
isFinite = \case
  Fin {} -> True
  Infinity -> False

liftX :: Natural -> Maybe Point
liftX x0 = do
  guard $ x0 < kp
  let x :: Fp
      !x = fromIntegral @_ @Fp x0
      !c = x * x * x + 7
      !y = c ^ ((kp + 1) `quot` 4)
  guard $ c == y * y
  pure $
    if even $ fromFp y
      then Fin x y
      else Fin x (-y)

fromFp :: Fp -> Natural
fromFp = unMod . unFp

kp :: Natural
kp = natVal @P Proxy

toPointAndAdjust :: Natural -> (Natural, Point)
toPointAndAdjust d' =
  let !p = d' *. g
      !d
        | evenY p = d'
        | otherwise = order - d'
   in (d, p)

zipWithBytes32 :: (Word8 -> Word8 -> Word8) -> Bytes32 -> Bytes32 -> Bytes32
{-# INLINE zipWithBytes32 #-}
zipWithBytes32 f = fmap unsafeFromPrimVector . PV.zipWith f `on` toPrimVector

toPrimVector :: Bytes32 -> PV.Vector Word8
{-# INLINE toPrimVector #-}
toPrimVector =
  getBytes32
    >>> \(SBS ba#) -> PV.Vector 0 32 (ByteArray ba#)

unsafeFromPrimVector :: PV.Vector Word8 -> Bytes32
{-# INLINE unsafeFromPrimVector #-}
unsafeFromPrimVector = \case
  PV.Vector 0 _ (ByteArray ba#) -> Bytes32 (SBS ba#)
  PV.Vector n _ (ByteArray ba#) ->
    runST $ do
      mba <- BA.unsafeThawByteArray (ByteArray ba#)
      ByteArray ba'# <- BA.freezeByteArray mba n 32
      pure $ Bytes32 $ SBS ba'#

data Signature = Signature !Bytes32 !Bytes32
  deriving (Show, Eq, Ord)

instance ToJSON Signature where
  toJSON (Signature l r) =
    toJSON $ (shows l . shows r) ""

instance FromJSON Signature where
  parseJSON = withText "hexa of 64-digits" $ \txt -> do
    let !len = T.length txt
    when (len /= 64) $
      fail $
        "Length must be 64, but got: "
          <> show len
    let (lh, rh) = T.splitAt 32 txt
    maybe
      (fail "Not a hex string")
      pure
      $ (Signature `on` naturalToBytes32)
        <$> readHexMaybe (T.unpack lh)
        <*> readHexMaybe (T.unpack rh)

parseSignature :: BS.ByteString -> Maybe Signature
{-# INLINE parseSignature #-}
parseSignature sig = do
  guard $ BS.length sig == 64
  let (lh, rh) = BS.splitAt 32 sig
  pure $ Signature (unsafeFromByteString lh) (unsafeFromByteString rh)

fromSignature :: Signature -> BS.ByteString
{-# INLINE fromSignature #-}
fromSignature = \case
  Signature l r -> toByteString l <> toByteString r

class FromBytes32 a where
  parseFromBytes32 :: Bytes32 -> Either String a
  encodeBytes32 :: a -> Bytes32

instance FromBytes32 Bytes32 where
  parseFromBytes32 = pure
  {-# INLINE parseFromBytes32 #-}
  encodeBytes32 = id
  {-# INLINE encodeBytes32 #-}

instance FromBytes32 PublicKey where
  parseFromBytes32 = pure . PublicKey
  {-# INLINE parseFromBytes32 #-}
  encodeBytes32 = rawPublicKey
  {-# INLINE encodeBytes32 #-}

instance FromBytes32 SecretKey where
  parseFromBytes32 = maybe (Left "Invalid secret key") pure . toSecretKey
  {-# INLINE parseFromBytes32 #-}
  encodeBytes32 = _rawSecretKey
  {-# INLINE encodeBytes32 #-}
