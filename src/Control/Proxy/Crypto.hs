{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Control.Proxy.Crypto
    ( hashD
    ) where

--------------------------------------------------------------------------------
import Control.Applicative
import Control.Monad (forever)
import Control.Proxy ((>>~), (>->))
import Data.ByteString (ByteString)
import Data.Monoid

--------------------------------------------------------------------------------
import qualified Data.ByteString as BS
import qualified Data.Tagged as Tagged
import qualified Crypto.Classes as Crypto
import qualified Control.Proxy as Pipes
import qualified Control.Proxy.Trans.State as State

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
