{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Network.Social.Nostr.Bech32 (
  parsePublicKey,
  parseBech32PublicKey,
  parseSecretKey,
  parseBech32SecretKey,

  -- * Convenient wrappers
  Bech32Prefix,
  FromBytes32 (..),
  Bech32 (..),
  Bech32OrHex (..),
  parseBech32Bytes32Like,
  parseBytes32LikeBech32OrHex,
  encodeBech32Bytes32Like,

  -- * Low-level combinators
  parseBech32BytesWithPrefix,
  parseBech32Bytes,
  encodeBech32Bytes,
) where

import Codec.Binary.Bech32 (humanReadablePartFromText)
import qualified Codec.Binary.Bech32 as Bech32
import Control.Monad (when, (<=<))
import Crypto.Signature.Schorr.Secp256k1
import Data.Aeson
import qualified Data.Bifunctor as Bi
import Data.Tagged
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Exts (proxy#)
import GHC.Generics (Generic)
import GHC.TypeLits

newtype Bech32 a = Bech32 {runBech32 :: a}
  deriving (Show, Eq, Ord, Generic)
  deriving newtype (FromBytes32)

newtype Bech32OrHex a = Bech32OrHex {runBech32Orhex :: a}
  deriving (Show, Eq, Ord, Generic)
  deriving newtype (FromBytes32)

type family Bech32Prefix a :: Symbol

type instance Bech32Prefix SecretKey = "nsec"

type instance Bech32Prefix PublicKey = "npub"

type instance Bech32Prefix (Bech32 a) = Bech32Prefix a

instance (FromBytes32 a, KnownSymbol (Bech32Prefix a)) => FromJSON (Bech32 a) where
  {-# INLINE parseJSON #-}
  parseJSON =
    withText "bech32-encoded 32-bytes text" $
      either fail (pure . Bech32) . parseBech32Bytes32Like

instance (FromBytes32 a, KnownSymbol (Bech32Prefix a)) => ToJSON (Bech32 a) where
  {-# INLINE toJSON #-}
  toJSON = toJSON . encodeBech32Bytes32Like . runBech32

instance (FromBytes32 a, KnownSymbol (Bech32Prefix a)) => FromJSON (Bech32OrHex a) where
  {-# INLINE parseJSON #-}
  parseJSON =
    withText "bech32-encoded 32-bytes text" $
      either fail (pure . Bech32OrHex) . parseBytes32LikeBech32OrHex

-- | __N.B.__ Uses bech32-encoding
instance (FromBytes32 a, KnownSymbol (Bech32Prefix a)) => ToJSON (Bech32OrHex a) where
  {-# INLINE toJSON #-}
  toJSON = toJSON . encodeBech32Bytes32Like . runBech32Orhex

parseBech32Bytes32Like ::
  forall a.
  (FromBytes32 a, KnownSymbol (Bech32Prefix a)) =>
  Text ->
  Either String a
{-# INLINE parseBech32Bytes32Like #-}
parseBech32Bytes32Like =
  parseFromBytes32
    <=< parseBech32BytesWithPrefix (unTagged $ prefixOf @a)

prefixOf :: forall a. KnownSymbol (Bech32Prefix a) => Tagged a Text
prefixOf = Tagged (T.pack $ symbolVal' @(Bech32Prefix a) proxy#)

encodeBech32Bytes32Like ::
  forall a.
  (FromBytes32 a, KnownSymbol (Bech32Prefix a)) =>
  a ->
  Either String Text
encodeBech32Bytes32Like inp = do
  prfx <- Bi.first show $ humanReadablePartFromText (unTagged $ prefixOf @a)
  Bi.first show $
    Bech32.encode prfx $
      Bech32.dataPartFromBytes $
        toByteString $
          encodeBytes32 inp

parseBytes32LikeBech32OrHex ::
  forall a.
  (FromBytes32 a, KnownSymbol (Bech32Prefix a)) =>
  Text ->
  Either String a
{-# INLINE parseBytes32LikeBech32OrHex #-}
parseBytes32LikeBech32OrHex inp
  | (unTagged (prefixOf @a) <> "1") `T.isPrefixOf` inp =
      parseFromBytes32
        =<< parseBech32BytesWithPrefix (unTagged $ prefixOf @a) inp
  | otherwise = parseFromBytes32 =<< parseHexBytes32 inp

parsePublicKey :: Text -> Either String PublicKey
parsePublicKey inp
  | "npub" `T.isPrefixOf` inp = parseBech32Bytes32Like inp
  | otherwise = PublicKey <$> parseHexBytes32 inp

parseBech32PublicKey :: Text -> Either String PublicKey
parseBech32PublicKey inp = PublicKey <$> parseBech32BytesWithPrefix "npub" inp

parseBech32SecretKey :: Text -> Either String SecretKey
parseBech32SecretKey inp = do
  bytes <- parseBech32BytesWithPrefix "nsec" inp
  maybe (Left "Invalid secret key") pure $ toSecretKey bytes

parseSecretKey :: Text -> Either String SecretKey
parseSecretKey inp
  | "nsec" `T.isPrefixOf` inp = do
      parseBech32SecretKey inp
  | otherwise = do
      b32 <- parseHexBytes32 inp
      maybe (Left "Invalid secret key") pure $ toSecretKey b32

parseBech32BytesWithPrefix :: Text -> Text -> Either String Bytes32
parseBech32BytesWithPrefix prfx src = do
  (readable, dataPart) <- Bi.first show $ Bech32.decode src
  let prfx' = Bech32.humanReadablePartToText readable
  when (prfx /= prfx') $
    Left $
      "bech32 prefix mismatched; expected: " <> T.unpack prfx <> ", but got: " <> T.unpack prfx'
  bs <-
    maybe (Left "Failed to decode bech32 payload") pure $
      Bech32.dataPartToBytes dataPart
  maybe (Left "Illegal byte sequence") pure $ fromByteString bs

encodeBech32Bytes :: Text -> Bytes32 -> Either String Text
encodeBech32Bytes prfx bytes = do
  let bs = toByteString bytes
  prefix <- Bi.first show $ Bech32.humanReadablePartFromText prfx
  Bi.first show $ Bech32.encode prefix $ Bech32.dataPartFromBytes bs

parseBech32Bytes :: Text -> Either String (Text, Bytes32)
parseBech32Bytes inp = do
  (readable, dataPart) <- Bi.first show $ Bech32.decode inp
  let prefix = Bech32.humanReadablePartToText readable
  bs <-
    maybe (Left "Failed to decode bech32 payload") pure $
      Bech32.dataPartToBytes dataPart
  bytes <- maybe (Left "Illegal byte sequence") pure $ fromByteString bs
  pure (prefix, bytes)
