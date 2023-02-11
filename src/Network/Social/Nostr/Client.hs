{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Network.Social.Nostr.Client (
  Relay (..),
  parseRelayUri,
  formatRelayUri,
  replyTextEvent,
  quoteTextEvent,
  pubKeyTagsFor,
) where

import Control.Monad (when, (<=<))
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as J
import qualified Data.HashSet as HS
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Vector as V
import GHC.Generics (Generic)
import Network.Social.Nostr.Types
import Network.URI (URI (..), URIAuth (..), parseURI)
import Text.Read (readMaybe)

data Relay = Relay
  { relayHost :: !String
  , relayPort :: !Int
  , relayEndPoint :: !String
  }
  deriving (Show, Eq, Ord, Generic)

instance FromJSON Relay where
  parseJSON = either fail pure . parseRelayUri <=< J.parseJSON
  {-# INLINE parseJSON #-}

instance ToJSON Relay where
  toJSON = J.toJSON . formatRelayUri
  {-# INLINE toJSON #-}

formatRelayUri :: Relay -> Text
formatRelayUri Relay {..} =
  let path
        | relayEndPoint == "/" = ""
        | otherwise = T.pack relayEndPoint
      port
        | relayPort /= 443 = ":" <> T.pack (show relayPort)
        | otherwise = ""
   in "wss://" <> T.pack relayHost <> port <> path

parseRelayUri :: String -> Either String Relay
parseRelayUri input = do
  uri <- maybe (Left "Invalid URI") pure $ parseURI input
  when (uriScheme uri /= "wss:") $
    Left $
      "URI scheme must be `wss' but got: " <> show (uriScheme uri)
  uriAuth <- maybe (Left "URI must be have authority") pure $ uriAuthority uri
  let relayHost = uriRegName uriAuth
  relayPort <-
    if null (uriPort uriAuth)
      then pure 443
      else
        maybe (Left $ "Invalid port number: " <> show (uriPort uriAuth)) pure $
          readMaybe (uriPort uriAuth)
  let path0 = uriPath uri
      relayEndPoint
        | null path0 = "/"
        | otherwise = path0
  pure Relay {..}

replyTextEvent :: Relay -> Event -> [Tag]
replyTextEvent relay evt@Event {eventBody = EventBody {..}, ..} =
  let es = V.mapMaybe (parseTagMaybe @EventTag) tags
      tag0 =
        EventTag
          { evtRecommendedRelay = Just $ formatRelayUri relay
          , evtMarker = Just Reply
          , evtEventId = eventId
          }
      root =
        fromMaybe tag0 {evtMarker = Just Root} $
          V.find ((== Just Root) . evtMarker) es
      evts
        | evtEventId root == eventId = [root]
        | otherwise = [tag0, root]
      pks = map encodeTag $ pubKeyTagsFor relay evt
   in map encodeTag evts ++ pks

quoteTextEvent :: Relay -> Event -> [Tag]
quoteTextEvent relay evt@Event {..} =
  let tag0 =
        EventTag
          { evtRecommendedRelay = Just $ formatRelayUri relay
          , evtMarker = Just Mention
          , evtEventId = eventId
          }
      pks = map encodeTag $ pubKeyTagsFor relay evt
   in encodeTag tag0 : pks

pubKeyTagsFor :: Relay -> Event -> [PubKeyTag]
pubKeyTagsFor relay Event {eventBody = EventBody {..}} =
  HS.toList $
    HS.fromList $
      PubKeyTag
        { pkRecommendedRelay = Just $ formatRelayUri relay
        , pkPubKey = pubkey
        }
        : V.toList (V.mapMaybe parseTagMaybe tags)
