{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Control.Proxy.Crypto
    ( hashD
    , hmacD
    ) where

--------------------------------------------------------------------------------
import Control.Applicative
import Control.Monad (forever)
import Control.Proxy ((>>~), (>->))
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.Monoid
import Data.Word ()


--------------------------------------------------------------------------------
import qualified Crypto.Classes as Crypto
import qualified Crypto.HMAC as Crypto
import qualified Control.Proxy as Pipes
import qualified Control.Proxy.Trans.State as State
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Serialize as S
import qualified Data.Tagged as Tagged


--------------------------------------------------------------------------------
-- | Hash the content flowing downstream in a 'Pipes.Proxy'.
hashD :: forall ctx p m d a' a. (Monad m, Crypto.Hash ctx d, Pipes.Proxy p) =>
    (() -> p a' a () ByteString m ()) -> () -> p a' a () d m ()
hashD source = wrapD source >-> streamingHash

  where

    streamingHash = const $
        State.evalStateP mempty $ go (Crypto.initialCtx :: ctx)

      where

        blockSize = Crypto.blockLength `Tagged.witness` (undefined :: d)

        go !ctx = do
            res <- Pipes.request ()
            case res of
                Just a -> do
                    allData <- BS.append <$> State.get <*> pure a
                    let blocks = floor (fromIntegral (BS.length allData) /
                                        fromIntegral blockSize :: Float)
                        (consumed, leftOver) = BS.splitAt (blocks * blockSize) allData
                    State.put leftOver
                    go (Crypto.updateCtx ctx consumed)
                Nothing -> do
                    leftOver <- State.get
                    Pipes.respond $ Crypto.finalize ctx leftOver


--------------------------------------------------------------------------------
-- | Calculate the HMAC of all values flowing downstream, for a given
-- 'Crypto.MacKey'.
hmacD :: forall ctx p m d a' a.
  (Monad m, Crypto.Hash ctx d, Pipes.Proxy p, Monad (p a' a () ByteString m)) =>
    Crypto.MacKey ctx d -> (() -> p a' a () ByteString m ()) ->
    () -> p a' a () d m ()
hmacD (Crypto.MacKey key) source =
    hashD (\x -> Pipes.respond kI >> source x) >->
    const (Pipes.runIdentityP $ do
             inner :: d <- Pipes.request ()
             Pipes.respond . Crypto.hash . LBS.fromChunks $
               [ kO, S.encode inner ])

  where

    cap k = if BS.length k > blockSize
              then S.encode (Crypto.hash' k :: d)
              else k

    pad k = let remaining = blockSize - BS.length k
            in if remaining > 0
              then k `BS.append` BS.replicate remaining 0x00
              else k

    blockSize = (Crypto.blockLength `Tagged.witness` (undefined :: d)) `div` 8

    key' = pad . cap $ key

    kO = BS.map (`xor` 0x5c) key'

    kI = BS.map (`xor` 0x36) key'


--------------------------------------------------------------------------------
wrapD :: (Monad m, Pipes.Proxy p) =>
    (b' -> p a' a b' b m r) -> b' -> p a' a b' (Maybe b) m r
wrapD source = only . source
  where
    only p = Pipes.runIdentityP $ do
        Pipes.IdentityP p >>~ wrap
        forever $ Pipes.respond Nothing
    wrap a = do
        a' <- Pipes.respond (Just a)
        a2 <- Pipes.request a'
        wrap a2
