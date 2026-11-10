# biscuit-ssh-service

The plumbing shared by the services of [biscuit-ssh](https://github.com/davlgd/biscuit-ssh), which gives SSH access through [Biscuit](https://www.biscuitsec.org/) tokens. This crate reads revocation lists, sets up logging, and handles shutdown. Two features add the rest:

- `authority`: the token verifier and the certificate signer of the issuer and the bastion
- `http`: an HTTP API server over TLS

It's a building block of the biscuit-ssh services. Its API follows their needs, and may change with any 0.x release.

The [repository](https://github.com/davlgd/biscuit-ssh) explains the concepts, and how to deploy and use biscuit-ssh.
