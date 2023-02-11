{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GHC2021 #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Crypto.RNG (newCryptoRNGState, runCryptoRNGT)
import Crypto.Signature.Schorr.Secp256k1
import Data.Aeson (FromJSON)
import Data.Aeson qualified as J
import Data.Yaml qualified as Y
import Network.Social.Nostr.Bech32
import Network.Social.Nostr.Types
import Network.URI
import Network.WebSockets
import Options.Applicative qualified as Opt
import Path
import RIO
import RIO.Orphans ()
import Wuss (runSecureClient)

data Relay = Relay
  { relayHost :: !String
  , relayPort :: !Int
  , relayEndPoint :: !String
  }
  deriving (Show, Eq, Ord, Generic)

instance FromJSON Relay where
  parseJSON = either fail pure . parseRelayUri <=< J.parseJSON
  {-# INLINE parseJSON #-}

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

data PostSimpleConfig = PostSimpleConfig
  { secretKey :: Bech32OrHex SecretKey
  , relays :: NonEmpty Relay
  }
  deriving (Show, Eq, Ord, Generic)
  deriving anyclass (FromJSON)

data Options = Options
  { configPath :: !(SomeBase File)
  , note :: !Text
  }
  deriving (Show, Eq, Ord, Generic)

optionsP :: Opt.ParserInfo Options
optionsP = Opt.info p $ Opt.progDesc "Simple Nostr client that posts a single note to the specified relays"
  where
    p = do
      configPath <-
        Opt.option (Opt.maybeReader parseSomeFile) $
          Opt.long "config"
            <> Opt.value defaultConfigPath
            <> Opt.showDefault
            <> Opt.short 'c'
            <> Opt.metavar "FILE"
            <> Opt.help "Path to the configuration yaml file"
      note <-
        Opt.strArgument $
          Opt.metavar "TEXT" <> Opt.help "The body of the note to post"
      pure Options {..}

defaultConfigPath :: SomeBase File
defaultConfigPath =
  Rel $
    [reldir|config|] </> [relfile|post-simple.yaml|]

main :: IO ()
main = runSimpleApp $ do
  Options {..} <- liftIO $ Opt.execParser optionsP
  PostSimpleConfig {..} <- Y.decodeFileThrow $ fromSomeFile configPath
  logInfo $ "Posting: " <> display note
  now <- getCurrentTimestamp
  let sk = runBech32Orhex secretKey
      pk = toPublicKey sk
  logDebug $ "Public Key: " <> displayShow pk
  let evt =
        EventBody
          { tags = mempty
          , pubkey = pk
          , kind = TextNote
          , createdAt = now
          , content = note
          }
  rng <- newCryptoRNGState
  signedEvt <- runCryptoRNGT rng $ signEventM sk evt
  forConcurrently_ relays $ \Relay {..} -> handleAny (\err -> logError $ fromString relayHost <> ": Error " <> displayShow err) $ do
    logInfo $ "Posting to: " <> fromString relayHost
    withRunInIO $ \runInIO -> do
      runSecureClient relayHost (fromIntegral relayPort) relayEndPoint $ \conn -> runInIO $ do
        mapM_ (sendMessage conn) [ClientEvent signedEvt]
          `race_` forever
            ( recvMessage conn >>= \msg ->
                logInfo $ fromString relayHost <> ": " <> displayShow msg
            )

sendMessage ::
  (MonadIO m, MonadReader env m, HasLogFunc env) =>
  Connection ->
  ClientMessage ->
  m ()
sendMessage conn payload = do
  logDebug $ "Sending: " <> displayShow (J.encode payload)
  liftIO . sendTextData conn . J.encode $ payload
  logDebug "Sent!"

recvMessage :: MonadIO m => Connection -> m (Either String RelayMessage)
recvMessage = liftIO . fmap J.eitherDecode . receiveData
