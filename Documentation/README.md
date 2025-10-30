# Steps:

1-Go to the root and compile the java files from client and server folders
`Example command in Windows:`
" javac -Xlint:unchecked server\*.java client\crypto\*.java client\*.java"

2- go to the server path and run it
`Example command in Windows:`
"java BlockStorageServer"

3-go to the client path and test
`Example commands:`
- java CLTest PUT .\clientfiles\find.txt "keyword1 keyword2" or java CLTest PUT .\clientfiles\find.txt "keyword1,keyword2"
- java CLTest SEARCH keyword1
- java CLTest GET keyword2 retrieved (this way it will put the retrived file in a folder named "retrieved" inside 
  the client folder, but you can also place it in another path)
- java CLTest GET find.txt retrieve
- java CLTest GET CHECKINTEGRITY clientfiles\find.txt
- java CLTest LIST

# Configuration File: cryptoconfig.txt*

`Example 1 — AES/GCM`
ALG = AES_GCM
DATAKEYSIZEBITS = 256

`Example 2 — AES/CBC + HMAC`
ALG = AES_CBC_HMAC
DATAKEYSIZEBITS = 256
MACKEYSIZEBITS = 256

`Example 3 — ChaCha20-Poly1305`
ALG = CHACHA20_POLY1305
DATAKEYSIZEBITS = 256


Name:Nicole Arquissandas
StudentNumber:75026

