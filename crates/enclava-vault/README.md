# enclava-vault

A forward proxy that keeps real API credentials away from the workload that
uses them. Design and threat model: enclava-labs/enclava-paas#435.

The workload holds a placeholder such as `encv_github_0e7c…` and sends its
requests through the proxy (`HTTPS_PROXY`). For an origin that has a
connection, the proxy terminates the workload's TLS with a leaf minted from
its own CA, swaps the placeholder for the real credential, and forwards the
request over a new TLS connection verified against the public web roots.

## Status

This crate is the proxy only. It is not yet rendered into workload pods, has
no image, and nothing provisions it. Until callers are authenticated, `serve`
refuses to listen on anything but loopback.

## What a placeholder is allowed to do

A placeholder is swapped only when all of these hold:

- the request is on a tunnel to the connection's exact origin, and its
  `Host` or `:authority` names that origin;
- the path has no dot segments, encoded slashes or backslashes, and lies
  under the connection's path prefix (compared by whole segments);
- the placeholder sits in the one position the connection declares: inside a
  named header, as the value of a named query parameter, inside
  `Authorization: Basic` credentials, or inside the path.

Two limits on what can be declared: a hop-by-hop header such as
`Proxy-Authorization` cannot be a position, because the proxy never forwards
those, and a path credential cannot contain `/` or `\`. After a credential is
written into the path, the result is checked against the same path rules
again.

A known placeholder anywhere else in the request head fails the request with
`403` and an `x-enclava-vault: <reason>` header; nothing is forwarded.

Other behaviour worth knowing:

- Only `CONNECT` is served. An origin with no connection is refused unless it
  is on the pass-through list, in which case bytes are relayed untouched.
- When the last connection for an origin is removed, tunnels already open to
  it stop forwarding.
- The upstream is always the tunnel's origin; the request cannot redirect it.
- Every outbound dial resolves the name in the proxy and is refused if any
  answer is in a blocked network (loopback, RFC 1918, link-local, CGNAT, ULA).
  `serve` also blocks the comma-separated CIDRs in `CLUSTER_POD_CIDR` and
  `CLUSTER_SERVICE_CIDR`; set them when the cluster uses other ranges.
- Request bodies are not inspected. A placeholder in a body is never swapped.
- Requests that ask for a protocol upgrade (WebSocket) are refused with `501`.
- Responses are passed through unmodified. An upstream endpoint that echoes
  the credential back will show it to the workload; use the path prefix to
  keep such endpoints out of reach.

## Usage

```bash
# Store a credential. Prints the placeholder to hand to the workload.
enclava-vault connection set --store-dir /var/lib/vault \
  --name github --origin https://api.github.com \
  --header Authorization --expose-as GITHUB_TOKEN --secret-file ./token

enclava-vault connection list --store-dir /var/lib/vault
enclava-vault connection rm   --store-dir /var/lib/vault --name github

# Run the proxy and write the CA certificate the workload must trust.
enclava-vault serve --store-dir /var/lib/vault \
  --ca-cert-out /run/vault/ca.crt --passthrough https://example.com
```

Setting a connection that already exists replaces its credential and keeps
its placeholder. A running proxy picks up changes without a restart.

## Storage

`--store-dir` holds one `0600` file per connection and `ca.pem`, the CA key
and certificate. Changes take an exclusive lock on the directory and are
synced to it before a command reports success, so concurrent commands and a
first start racing another agree on one placeholder and one CA.

`--ca-cert-out` must point outside the store directory; `serve` refuses a
path inside it, because that is where the CA key lives.

The directory must live somewhere the workload cannot read; the crate sets
owner-only modes and marks the process non-dumpable, and relies on the
deployment for the rest.
