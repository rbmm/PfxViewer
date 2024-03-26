tool for work with PFX/PEM files

PFXviewer.exe let you view context of pfx and pem files
PfxToPem.exe convert pfx to pem and pem to pfx

for decrypt private key in ENCRYPTED PRIVATE KEY and PRIVATE KEY
the NCryptImportKey can be used with NCRYPT_PKCS8_PRIVATE_KEY_BLOB (in case ENCRYPTED need provide NCRYPTBUFFER_PKCS_SECRET type buffer)
but all NCrypt* calls is rpc to ncryptprov.dll in lsass, so relative slow
in [Pkcs.cpp](https://github.com/rbmm/PfxViewer/blob/main/Pem/Pkcs.cpp) i provide own implementation (of course only reverse of NCryptImportKey internal work ) for this
PkcsImportPlainTextKey and PkcsImportEncodedKey. 
it use bcrypt instead ncrypt and all calls in process, as result relative fast, and look like not known, if based on goole search
look for DecryptPrivateKey implementation in Pkcs.cpp

Pem project is demo only for test bcrypt implementation of CryptImportKey(..NCRYPT_PKCS8_PRIVATE_KEY_BLOB..) and how to parse pem file (concept only)
