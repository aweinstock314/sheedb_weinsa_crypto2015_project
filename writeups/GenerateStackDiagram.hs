{-# LANGUAGE NoMonomorphismRestriction, QuasiQuotes #-}
import Text.Printf.TH

emitBox w h x y = [s|\\draw (%?,%?) -- (%?,%?) -- (%?,%?) -- (%?,%?)-- (%?,%?);|] x y (x+w) y (x+w) (y-h) x (y-h) x y

memBox x y addr str = concat [box, text, addrLabel, line] where
    box = emitBox 9.1 h1 x y
    text = [s|\\draw (%?,%?) node[right]{\\Verb|%s|};|] (x+sep) (y-h2) str
    addrLabel = [s|\\draw (%?, %?) node[right]{\\verb|%s|};|] x (y-h2) addr
    line = [s|\\draw (%?,%?) -- (%?, %?);|] (x+sep) y (x+sep) (y-h1)
    sep = 2.5; h1 = 0.75; h2 = 0.25

stackFrame x y title contents = concat $ titleNode : frameNodes where
    titleNode = [s|\\draw (%?,%?) node[right]{\\Verb|%s|};|] x (y+0.25) title
    frameNodes = zipWith3 (\x y (a,z) -> memBox x y a z) (repeat x) [y,y-0.75..] contents

offset y i = y - (0.75 * i) - 0.3

arrow x1 x2 x3 y1 y2 = [s|\\draw[->] (%?,%?) -- (%?,%?) -- (%?,%?) -- (%?,%?);|] x1 y1 x2 y1 x2 y2 x3 y2 where

ebp = [s|EBP %c %4x|]
stackDiagram = concat $ [
    --stackFrame 7 10 "alphabet" ["hello", "world"],
    stackFrame 1 aesFrame "bank_aes_handshake arguments" [
        (ebp '+' 0x08, "int client_fd"),
        (ebp '+' 0x0c, "PrivateKey &privateKey"),
        (ebp '+' 0x10, "PublicKey &publicKey"),
        (ebp '+' 0x14, "byte* aes_key"),
        (ebp '+' 0x18, "byte* iv"),
        (ebp '+' 0x1c, "std::string& init_nonce")
        ],
    stackFrame 11.5 threadFrame "thread_handle locals" [
        (ebp '-' 0x1cc, "std::string nonce"),
        (ebp '-' 0x1c0, "action::Action response"),
        (ebp '-' 0x100, "action::Action action"),
        (ebp '-' 0x0e0, "std::string s"),
        (ebp '-' 0x048, "byte iv[16]"),
        (ebp '-' 0x038, "int dummy_alloc"),
        (ebp '-' 0x034, "byte aes_key[16]"),
        (ebp '-' 0x024, "PublicKey *publicKey"),
        (ebp '-' 0x020, "PrivateKey *privateKey"),
        (ebp '-' 0x01c, "int client_sock"),
        (ebp '-' 0x018, "client_info *client_args")
        ],
    stackFrame 1 mainFrame "main locals" [
        (ebp '-' 0x29c, "int client_sock"),
        (ebp '-' 0x268, "char port_str[10]"),
        (ebp '-' 0x238, "client_info client_args"),
        (ebp '-' 0x238, "    client_args.sockfd"),
        (ebp '-' 0x234, "    client_args.privateKey"),
        (ebp '-' 0x230, "    client_args.publicKey"),
        (ebp '-' 0x22c, "pthread_t client_thread"),
        (ebp '-' 0x224, "socklen_t addr_size"),
        (ebp '-' 0x220, "struct sockaddr_storage client"),
        (ebp '-' 0x190, "int listen_sock"),
        (ebp '-' 0x18c, "struct addrinfo *res"),
        (ebp '-' 0x188, "struct addrinfo hints"),
        (ebp '-' 0x164, "pthread_t console_thread"),
        (ebp '-' 0x160, "PublicKey publicKey"),
        (ebp '-' 0x128, "PrivateKey privateKey"),
        (ebp '-' 0x028, "std::string inputPort")
    ],
    arrow 1 0.5 1 (offset aesFrame 1) (offset mainFrame 4),
    arrow 1 0 1 (offset aesFrame 2) (offset mainFrame 5),
    arrow 11.5 11.0 10.1 (offset threadFrame 8) (offset mainFrame 4),
    arrow 11.5 10.5 10.1 (offset threadFrame 7) (offset mainFrame 5),
    arrow 10.1 11.0 11.5 (offset aesFrame 3) (offset 5 6),
    arrow 10.1 10.5 11.5 (offset aesFrame 4) (offset 5 4)
    ] where
    aesFrame = 6; threadFrame = 5; mainFrame = 0

main = writeFile "stackDiagram.tikz" stackDiagram
