{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Control.Proxy.Crypto
    ( hashD
    , hmacD
    , ecbD
    ) where

--------------------------------------------------------------------------------
import Control.Applicative
import Control.Monad (when)
import Control.Proxy ((>->))
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
hashD :: forall ctx p m d y' y. (Monad m, Crypto.Hash ctx d, Pipes.Proxy p) =>
    () -> p () (Maybe ByteString) y' y m d
hashD () = State.evalStateP mempty $ go (Crypto.initialCtx :: ctx)

  where

    blockSize =
        Crypto.blockLength `Tagged.witness` (undefined :: d) `div` 8

    go !ctx = do
        res <- Pipes.request ()
        case res of
            Just a -> do
                consumed <- getBlocks a blockSize

                if not . BS.null $ consumed
                    then go (Crypto.updateCtx ctx consumed)
                    else go ctx

            Nothing -> do
                leftOver <- State.get
                return $ Crypto.finalize ctx leftOver


--------------------------------------------------------------------------------
-- | Calculate the HMAC of all values flowing downstream, for a given
-- 'Crypto.MacKey'.
hmacD :: forall ctx p m d y' y.
  (Monad m, Crypto.Hash ctx d, Pipes.Proxy p) =>
    Crypto.MacKey ctx d -> () -> p () (Maybe ByteString) y' y m d
hmacD (Crypto.MacKey key) () = Pipes.runIdentityP $ do
    h <- (prefix kI >-> hashD) ()
    return . Crypto.hash . LBS.fromChunks $
        [ kO, S.encode (h :: d) ]

  where

    prefix x () = Pipes.respond (Just x) >>= Pipes.pull

    cap k = if BS.length k > blockSize
              then S.encode (Crypto.hash' k :: d)
              else k

    pad k = let remaining = blockSize - BS.length k
            in if remaining > 0
              then k `BS.append` BS.replicate remaining 0x00
              else k

    blockSize = (Crypto.blockLength `Tagged.witness`
                    (undefined :: d)) `div` 8

    key' = pad . cap $ key

    kO = BS.map (`xor` 0x5c) key'

    kI = BS.map (`xor` 0x36) key'

--------------------------------------------------------------------------------
ecbD :: forall m k p. (Monad m, Crypto.BlockCipher k, Pipes.Proxy p) =>
    k -> () -> p () ByteString () ByteString m ()
ecbD k () = State.evalStateP mempty go

  where

    blockSize = Crypto.blockSize `Tagged.witness` (undefined :: k) `div` 8

    go = Pipes.request () >>= ecb

    ecb x = do
        consumed <- getBlocks x blockSize
        when (not . BS.null $ consumed) $ Pipes.respond (Crypto.ecb k x)
        go


--------------------------------------------------------------------------------
getBlocks :: (Monad m, Pipes.Proxy p) =>
    ByteString -> Int -> State.StateP ByteString p a' a b' b m ByteString
getBlocks a n = do
    allData <- BS.append <$> State.get <*> pure a

    let blocks = floor (fromIntegral (BS.length allData) /
                        fromIntegral n :: Float)

        (consumed, leftOver) = BS.splitAt (blocks * n) allData

    State.put leftOver

    return consumed

