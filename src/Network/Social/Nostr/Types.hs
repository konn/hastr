{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-partial-fields #-}

module Network.Social.Nostr.Types (
  Event (..),
  EventBody (..),
  Tag (..),
  TagParseError (..),
  IsTag (..),
  PubKeyTag (..),
  EventTag (..),
  EventMarker (..),
  encodeTag,
  parseTag,
  parseTagMaybe,
  AsTag (..),
  Timestamp (..),
  fromPOSIXTime,
  getCurrentTimestamp,
  verifyEvent,
  VerificationError (..),
  eventSummary,
  signEventM,
  signEventWith,
  ClientMessage (..),
  SubscriptionId (..),
  Filter (..),
  RelayMessage (..),
  EventKind (..),

  -- * Re-exports
  PublicKey (..),
  SecretKey (),
  Bytes32,
  parseHexBytes32,
  parseHexPublicKey,
  PetnameTag (..),
) where

import Control.Applicative (asum)
import Control.Exception (Exception)
import Control.Monad (unless, when, (<=<))
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Loops (untilJust)
import Crypto.RNG (CryptoRNG)
import Crypto.Signature.Schorr.Secp256k1
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as J
import qualified Data.Aeson.KeyMap as AK
import qualified Data.Bifunctor as Bi
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Char as C
import Data.Digest.Pure.SHA (sha256)
import Data.Hashable (Hashable)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe)
import Data.Tagged (Tagged (..))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import qualified Data.Vector as V
import GHC.Generics (Generic)
import Numeric.Natural (Natural)

data Event = Event
  { eventId :: {-# UNPACK #-} !Bytes32
  , eventSig :: {-# UNPACK #-} !Signature
  , eventBody :: {-# UNPACK #-} !EventBody
  }
  deriving (Show, Eq, Ord, Generic)

instance ToJSON Event where
  {-# INLINE toJSON #-}
  toJSON Event {..} =
    case J.toJSON eventBody of
      J.Object obj ->
        J.Object $
          AK.insert "sig" (J.toJSON eventSig) $
            AK.insert "id" (J.toJSON eventId) obj
      _ -> error "Impossible"

instance FromJSON Event where
  {-# INLINE parseJSON #-}
  parseJSON = J.withObject "event object" $ \dic -> do
    eventBody <- J.parseJSON $ J.Object dic
    eventId <- dic J..: "id"
    eventSig <- dic J..: "sig"
    pure Event {..}

newtype Timestamp = Timestamp {timeStampInPosixSeconds :: Int}
  deriving (Show, Eq, Ord, Generic)
  deriving newtype (FromJSON, ToJSON)

fromPOSIXTime :: POSIXTime -> Timestamp
fromPOSIXTime = Timestamp . floor

getCurrentTimestamp :: MonadIO m => m Timestamp
getCurrentTimestamp = fromPOSIXTime <$> liftIO getPOSIXTime

data EventKind = SetMetadata | TextNote | RecommendServer | ContactList | OtherKind !Int
  deriving (Show, Eq, Ord, Generic)

instance Enum EventKind where
  fromEnum SetMetadata = 0
  fromEnum TextNote = 1
  fromEnum RecommendServer = 2
  fromEnum ContactList = 3
  fromEnum (OtherKind n) = n
  toEnum 0 = SetMetadata
  toEnum 1 = TextNote
  toEnum 2 = RecommendServer
  toEnum 3 = ContactList
  toEnum n = OtherKind n

instance FromJSON EventKind where
  parseJSON = fmap toEnum <$> J.parseJSON
  {-# INLINE parseJSON #-}

instance ToJSON EventKind where
  toJSON = J.toJSON . fromEnum
  {-# INLINE toJSON #-}

data EventBody = EventBody
  { pubkey :: {-# UNPACK #-} !PublicKey
  , createdAt :: {-# UNPACK #-} !Timestamp
  , kind :: {-# UNPACK #-} !EventKind
  , tags :: {-# UNPACK #-} !(V.Vector Tag)
  , content :: {-# UNPACK #-} !Text
  }
  deriving (Show, Eq, Ord, Generic)

data Tag = Tag {tagName :: Text, tagBody :: V.Vector Text}
  deriving (Show, Eq, Ord, Generic)

instance FromJSON Tag where
  parseJSON obj = do
    strs <- J.parseJSON obj
    when (V.null strs) $
      fail "Tag must be represented as a non-empty array of strings"
    pure Tag {tagName = V.unsafeHead strs, tagBody = V.unsafeTail strs}

instance ToJSON Tag where
  toJSON Tag {..} = J.toJSON $ V.cons tagName tagBody
  {-# INLINE toJSON #-}

class IsTag a where
  tagIdentifier :: Tagged a Text
  toTagBody :: a -> V.Vector Text
  parseTagBody :: V.Vector Text -> Either String a

data TagParseError
  = TagIdentifierMismatched {expected :: Text, actual :: Text}
  | TagBodyParseError String
  deriving (Show, Eq, Ord, Generic)
  deriving anyclass (Exception)

encodeTag :: forall a. IsTag a => a -> Tag
encodeTag a = Tag {tagName = unTagged @a tagIdentifier, tagBody = toTagBody a}

parseTag :: forall a. IsTag a => Tag -> Either TagParseError a
parseTag Tag {..}
  | tagName == unTagged (tagIdentifier @a) =
      Bi.first TagBodyParseError $ parseTagBody tagBody
  | otherwise =
      Left
        TagIdentifierMismatched
          { expected = unTagged (tagIdentifier @a)
          , actual = tagName
          }

parseTagMaybe :: IsTag a => Tag -> Maybe a
parseTagMaybe = either (const Nothing) Just . parseTag

-- | Convenient wrapper for turning 'IsTag' instance to 'ToJSON' and 'FromJSON'.
newtype AsTag a = AsTag {getAsTag :: a}
  deriving (Show, Eq, Ord, Generic)

instance IsTag a => FromJSON (AsTag a) where
  parseJSON =
    either (fail . show) (pure . AsTag) . parseTag <=< J.parseJSON
  {-# INLINE parseJSON #-}

instance IsTag a => ToJSON (AsTag a) where
  toJSON = J.toJSON . encodeTag . getAsTag
  {-# INLINE toJSON #-}

data PetnameTag = PetnameTag
  { pnPubKey :: PublicKey
  , pnMainRelay :: Maybe Text
  , pnPetname :: Text
  }
  deriving (Show, Eq, Ord, Generic)
  deriving (FromJSON, ToJSON) via AsTag PetnameTag
  deriving anyclass (Hashable)

instance IsTag PetnameTag where
  tagIdentifier = "p"
  toTagBody PetnameTag {..} =
    V.fromList [T.pack $ show pnPubKey, fromMaybe "" pnMainRelay, pnPetname]
  parseTagBody = \case
    [rawKey, mrelay, petname] -> do
      pnPubKey <- parseHexPublicKey rawKey
      pure
        PetnameTag
          { pnPubKey
          , pnMainRelay = toNonEmptyText mrelay
          , pnPetname = petname
          }
    v ->
      Left $
        "petname: payload must be of size 3, but got: "
          <> show v

data PubKeyTag = PubKeyTag
  { pkPubKey :: PublicKey
  , pkRecommendedRelay :: Maybe Text
  }
  deriving (Show, Eq, Ord, Generic)
  deriving (FromJSON, ToJSON) via AsTag PubKeyTag
  deriving anyclass (Hashable)

instance IsTag PubKeyTag where
  tagIdentifier = "p"
  toTagBody PubKeyTag {..} =
    V.fromList [T.pack $ show pkPubKey, fromMaybe "" pkRecommendedRelay]
  parseTagBody = \case
    [rawKey, recom] -> do
      pkPubKey <- parseHexPublicKey rawKey
      pure
        PubKeyTag
          { pkPubKey
          , pkRecommendedRelay = toNonEmptyText recom
          }
    v ->
      Left $
        "PubKeyTag: payload must be of size 2, but got: "
          <> show v

data EventTag = EventTag
  { evtEventId :: Bytes32
  , evtRecommendedRelay :: Maybe Text
  , evtMarker :: Maybe EventMarker
  }
  deriving (Show, Eq, Ord, Generic)
  deriving (FromJSON, ToJSON) via AsTag EventTag

data EventMarker = Reply | Root | Mention
  deriving (Show, Eq, Ord, Generic)

markerOpts :: J.Options
markerOpts =
  J.defaultOptions
    { J.allNullaryToStringTag = True
    , J.constructorTagModifier = map C.toLower
    }

instance FromJSON EventMarker where
  parseJSON = J.genericParseJSON markerOpts
  {-# INLINE parseJSON #-}

instance ToJSON EventMarker where
  toJSON = J.genericToJSON markerOpts
  {-# INLINE toJSON #-}

instance IsTag EventTag where
  tagIdentifier = "e"
  toTagBody EventTag {..} =
    [ T.pack $ show evtEventId
    , fromMaybe "" evtRecommendedRelay
    , maybe "" (T.toLower . T.pack . show) evtMarker
    ]
  parseTagBody = \case
    [rawBytes, recom] -> do
      evtEventId <- parseHexBytes32 rawBytes
      pure
        EventTag
          { evtEventId
          , evtRecommendedRelay = toNonEmptyText recom
          , evtMarker = Nothing
          }
    [rawBytes, recom, marker] -> do
      evtEventId <- parseHexBytes32 rawBytes
      evtMarker <-
        case marker of
          "" -> pure Nothing
          "reply" -> pure $ Just Reply
          "root" -> pure $ Just Root
          "mention" -> pure $ Just Mention
          otr -> Left $ "Event marker must be one of `reply', `root', `mention', or just an empty string, but got: " <> show otr
      pure
        EventTag
          { evtEventId
          , evtRecommendedRelay = toNonEmptyText recom
          , evtMarker
          }
    v ->
      Left $
        "EventTag: payload must be of size 2 or 3, but got: "
          <> show v

toNonEmptyText :: Text -> Maybe Text
toNonEmptyText txt
  | T.null txt = Nothing
  | otherwise = Just txt

evtOption :: J.Options
evtOption =
  J.defaultOptions
    { J.fieldLabelModifier = J.camelTo2 '_'
    }

instance FromJSON EventBody where
  parseJSON = J.genericParseJSON evtOption
  {-# INLINE parseJSON #-}

instance ToJSON EventBody where
  toJSON = J.genericToJSON evtOption
  {-# INLINE toJSON #-}

signEventM :: CryptoRNG m => SecretKey -> EventBody -> m Event
signEventM sk evt = untilJust $ do
  seed <- randomSeed
  case signEventWith seed sk evt of
    Right ans -> pure $ Just ans
    Left {} -> pure Nothing

signEventWith :: Seed -> SecretKey -> EventBody -> Either String Event
signEventWith seed sk eventBody = do
  let eventId = calcEventId eventBody
  eventSig <- sign seed sk eventId
  pure Event {..}

calcEventId :: EventBody -> Bytes32
calcEventId evt =
  fromSHA256 $ sha256 $ eventSummary evt

eventSummary :: EventBody -> LBS.ByteString
eventSummary EventBody {..} =
  J.encode @[J.Value]
    [ J.Number 0
    , J.toJSON pubkey
    , J.toJSON createdAt
    , J.toJSON kind
    , J.toJSON tags
    , J.toJSON content
    ]

data VerificationError
  = InvalidEventId {_expected :: Bytes32, _got :: Bytes32}
  | InvalidSignature
  deriving (Show, Eq, Ord, Generic)

verifyEvent :: PublicKey -> Event -> Either VerificationError ()
verifyEvent pk Event {..} = do
  let anId = calcEventId eventBody
  when (anId /= eventId) $ Left $ InvalidEventId {_expected = anId, _got = eventId}
  unless (verify pk anId eventSig) $ Left InvalidSignature

data ClientMessage
  = ClientEvent Event
  | ClientReq SubscriptionId (NonEmpty Filter)
  | ClientClose SubscriptionId
  deriving (Show, Eq, Ord, Generic)

instance FromJSON ClientMessage where
  {-# INLINE parseJSON #-}
  parseJSON obj =
    asum @[]
      [ do
          ("EVENT" :: Text, evt) <- J.parseJSON obj
          pure $ ClientEvent evt
      , do
          "REQ" : subId : rest <- J.parseJSON obj
          subId' <- J.parseJSON subId
          filts <-
            maybe
              (fail "No filter specified")
              (mapM J.parseJSON)
              $ NE.nonEmpty rest
          pure $ ClientReq subId' filts
      , do
          ("CLOSE" :: Text, subscId) <- J.parseJSON obj
          pure $ ClientClose subscId
      ]

instance ToJSON ClientMessage where
  {-# INLINE toJSON #-}
  toJSON (ClientEvent evt) =
    J.toJSON ("EVENT" :: Text, evt)
  toJSON (ClientReq sid filts) =
    J.toJSON $
      J.String "REQ" : J.toJSON sid : map J.toJSON (NE.toList filts)
  toJSON (ClientClose sid) = J.toJSON ("CLOSE" :: Text, sid)

newtype SubscriptionId = SubscriptionId {subscriptionId :: Text}
  deriving (Show, Eq, Ord, Generic)
  deriving newtype (FromJSON, ToJSON)

data Filter = Filter
  { ids :: Maybe (NonEmpty Text)
  , authors :: Maybe (NonEmpty Text)
  , kinds :: Maybe (NonEmpty Natural)
  , eTag :: Maybe (NonEmpty Bytes32)
  , pTag :: Maybe (NonEmpty PublicKey)
  , since :: Maybe Timestamp
  , until :: Maybe Timestamp
  , limit :: Maybe Natural
  }
  deriving (Show, Eq, Ord, Generic)

filterOpts :: J.Options
filterOpts =
  J.defaultOptions
    { J.fieldLabelModifier = \tag ->
        case T.stripSuffix "Tag" $ T.pack tag of
          Just t -> '#' : T.unpack t
          Nothing -> tag
    , J.omitNothingFields = True
    }

instance J.ToJSON Filter where
  toJSON = J.genericToJSON filterOpts
  {-# INLINE toJSON #-}

instance J.FromJSON Filter where
  parseJSON = J.genericParseJSON filterOpts
  {-# INLINE parseJSON #-}

data RelayMessage
  = RelayEvent SubscriptionId Event
  | RelayNotice Text
  deriving (Show, Eq, Ord, Generic)

instance J.ToJSON RelayMessage where
  {-# INLINE toJSON #-}
  toJSON (RelayEvent sid evt) = J.toJSON ("EVENT" :: Text, sid, evt)
  toJSON (RelayNotice msg) = J.toJSON ("NOTICE" :: Text, msg)

instance J.FromJSON RelayMessage where
  parseJSON obj =
    asum @[]
      [ do
          ("EVENT" :: Text, subscId, evt) <- J.parseJSON obj
          pure $ RelayEvent subscId evt
      , do
          ("NOTICE" :: Text, text) <- J.parseJSON obj
          pure $ RelayNotice text
      ]
