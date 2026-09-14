# Direct Iota TAuth

Add `DirectIota` connection mode to binary `.ta` format and Rust SDK.

Direct sessions must implement same TAuth MTP messages, signed authorization checks, exact redirect and PKCE binding, discovery revalidation, scope enforcement, one-time codes, metadata limits, and atomic revocation used by Omikron-routed sessions. Direct raw MTP access must not bypass grant checks.
