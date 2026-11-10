# biscuit-ssh-core

The core of [biscuit-ssh](https://github.com/davlgd/biscuit-ssh), which gives SSH access through [Biscuit](https://www.biscuitsec.org/) tokens. This crate holds the Datalog vocabulary of tokens, and the verifier that decides whether a token allows a request, and for how long. It also mints, attenuates, and revokes tokens.

It's a building block of the biscuit-ssh services and client. Its API follows their needs, and may change with any 0.x release.

The [repository](https://github.com/davlgd/biscuit-ssh) explains the concepts, and how to deploy and use biscuit-ssh.
