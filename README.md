# solanacdn-protocol

Minimal SolanaCDN wire protocol used by the Agave validator integration.

This crate intentionally contains only:

- Wire message structs/enums (`messages`)
- Length-prefixed framing helpers (`frame`)
- UDP token framing helpers (`udp`)
- RaptorQ FEC helpers (`fec`)
- Small crypto helpers for delegation/auth payloads (`crypto`)
- Optional ledger memo helpers (`ledger_memos`, behind the `ledger-memos` feature)

It does **not** include any networking clients/servers, POP discovery, TLS configuration, or API key
logic. Those live in the validator integration (Agave fork) and in SolanaCDN private services.

## Versioning

- `messages::PROTOCOL_VERSION` gates envelope compatibility.
- Changes that break wire compatibility should bump `PROTOCOL_VERSION` and the crate version.

## License

GPL-3.0-only. See `LICENSE`.
