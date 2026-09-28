# Remote signer example

Run the reference HTTP server and its client signer together on loopback:

```sh
go run ./examples/remote-signer
```

The server creates an in-memory demo key, and the client asks it to authorize a
sample invocation through `remote.NewSigner`. The server-side `Approver`
callback prints the decoded preimage details before the reference server signs
it. The client then verifies the returned entry and prints its base64 XDR.

This is a local protocol example only; it does not submit a transaction to a
Stellar network. The reference server has no caller authentication, TLS,
authorization policy, or rate limiting. Anyone who can reach it can ask it to
sign. Do not expose it publicly or use it to protect production keys. A real
deployment needs authenticated and encrypted transport, authorization and
operational controls, and an appropriate key custody solution.