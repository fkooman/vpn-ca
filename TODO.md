# TODO

- switch to PKCS#8 for private key encoding (`PRIVATE KEY` instead of 
  `RSA PRIVATE KEY`)
- implement `server`, `client` directory for server and client certs
- allow CN only to contain the characters `[a-zA-Z0-9-.]`, i.e. pre-IDN 
  domain names

# Maybe

- try to create the CA dir if it is not there yet?
- can we simplify even more?
- use Ed25519 keys
- use separate dirs for server/client certs?
