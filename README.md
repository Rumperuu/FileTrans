# FileTrans
## (c) Ben Goldsworthy 2017

### Description

FileTrans is a program to securely connect to a server using Diffie-Hellman session keys in order to retrieve and decrypt an encrypted file.

### Running

To run the server:

   `java -jar diffiehellmanserver.jar <port> <p> <g> <secret> <filename>`
   
To run the client:

   `java -jar dh.jar <ip-address> <port> <p> <g> <secret>`
