User either has:
 - username and passowrd to authenticate with the server (gets sent as hash and then hashed again to be stored on the server)
 - key pair if wanted password protected to authenticate with the server

after authentication:
 - stateless session token (eg. JWT)

unclear:
 - how to transfer data?
    - SSE (Server Sent Events)
    - Websocket
 - how to encrypt the local messages?
    - only with the password?
    - when not used with password, maybe private key?
    - unencrypted
 - how to store session data securely? (doubleratchet state)
    - encrypted in database?
    - in encrypted binary file
    -
