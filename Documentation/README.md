# Steps:

1-Go to the each client's folder and compile the java files 
`Example command in Windows:`
"javac -Xlint:unchecked crypto\*.java iam\crypto\*.java *.java CLTest.java IamClient.java ClientCore.java"

2-Go to the server's folder and compile the java files
`Example command in Windows:`
" javac -Xlint:unchecked iam\crypto\*.java iam\servers\*.java BlockStorageServer.java"

3- go to the server path and run each server in the specified order
`Example command in Windows:`
"java BlockStorageServer"
"java iam.servers.OAServer"
"java iam.servers.OAMServer"

4-go to the client's path and test
`Example commands:`
- java CLTest PUT .\clientfiles\find.txt "keyword1 keyword2" or java CLTest PUT .\clientfiles\find.txt "keyword1,keyword2"
- java CLTest SEARCH keyword1
- java CLTest GET keyword2 retrieved (this way it will put the retrived file in a folder named "retrieved" inside 
  the client folder, but you can also place it in another path)
- java CLTest GET find.txt retrieve
- java CLTest GET CHECKINTEGRITY clientfiles\find.txt
- java CLTest LIST
- CLTest REG <password>
- CLTest REGMOD <oldPassword> <newPassword>
- CLTest REGDEL <password>
- CLTest LOGIN <password>
- CLTest SHOWPUB 
- CLTest SHARE <filename> <authorizedPubKeyB64> <GET|SEARCH|GET+SEARCH>
- CLTest SHAREDEL <filename> <authorizedPubKeyB64>
- CLTest GETSHARED <fileId> <path/dir/file>
- CLTest SEARCHSHARED <keywords>
- CLTest LISTSHARED

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

