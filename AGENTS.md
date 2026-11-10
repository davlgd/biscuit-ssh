# AGENTS.md

This file points coding agents to the instructions of biscuit-ssh, whose rules all apply to agents. Before you change anything, read [CONTRIBUTING.md](https://github.com/davlgd/biscuit-ssh/blob/main/CONTRIBUTING.md): the architecture, the code rules, and how to check a change.

## Before you report a change as done

- Run the [checks](https://github.com/davlgd/biscuit-ssh/blob/main/CONTRIBUTING.md#check-a-change): format, Clippy, and tests, with and without `certificates`
- Run `tests/e2e.sh` when the change affects what reaches `sshd`
- Update the doc comments, the README, `docs/certificates.md`, and the changelog in the same change
- Write the commit subject with the [commit conventions](https://github.com/davlgd/biscuit-ssh/blob/main/CONTRIBUTING.md#commit-messages)

Report a check you couldn't run, such as the end-to-end tests without a test deployment, rather than skipping it silently.

Keep the security rules of [CONTRIBUTING.md](https://github.com/davlgd/biscuit-ssh/blob/main/CONTRIBUTING.md#security) in mind as you write code. Never put a token, a private key, or the details of a real deployment in code, tests, logs, or commits.
