### Feature roadmap

- [ ] cli part [tag 0.0.1]
  - [x] internal repository
  - [x] persistance layer of internal repository
  - [x] flags handling
  - [x] db crypto check
  - [x] add zerolog logging support
  - [ ] add tests
- [ ] keys repository [tag 0.0.2]
  - [x] keys creation
  - [x] keys persistance
  - [x] keys deletion
  - [ ] implement key rotation mechanism
    ```
    When keys renewed client servers must be able to renew refresh jwt tokens signed with old keys
      - period to store old keys
      - key rotation process
        - rename old keys as 'kid_old'
        - store new keys as 'kid'
      - jwt renew process
        - when renew jwt requested get new keys
        - if sign or enc verification fails try to use old keys
    ```
  - [ ] add tests
- [ ] server-side [tag 0.1.1]
  - [x] add github.com/gin-gonic/gin HTTP web framework
  - [ ] add keys routes `/register` and `/keys`
  - [ ] add jwt routes `/issue_token` and `/renew_token`
  - [ ] add app's logger to server to log events
  - [ ] add tests
- [ ] client-side; middleware with automatic key fetching [tag 0.2.1]
  - [ ] http client to fetch public sign and encrypt keys
  - [ ] http middleware for jwt verification
  - [ ] add tests
  - [ ] \_optional jwt revoke client functionality
- [ ] Complete all tests [tag 1.0.1]
- [ ] add automatic tls support to server
  - [ ] [mkcert](https://github.com/FiloSottile/mkcert)
  - [ ] let's encrypt, eg [lego](https://github.com/xenolf/lego)
- [ ] additional features described in readme
