# biscuit-ssh-ca

The OpenSSH certificate authority of [biscuit-ssh](https://github.com/davlgd/biscuit-ssh), which gives SSH access through [Biscuit](https://www.biscuitsec.org/) tokens. The issuer and the bastion use this crate to sign short-lived user certificates, from an authorization of the verifier only.

It's a building block of the biscuit-ssh services and client. Its API follows their needs, and may change with any 0.x release.

The [repository](https://github.com/davlgd/biscuit-ssh) explains the concepts, and how to deploy and use biscuit-ssh.
