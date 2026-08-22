# Deploying openampd to the Sequentia testnet box

Turnkey deploy of the OpenAMP policy server alongside the public testnet node.
`openampd` talks to the node over RPC only; it never touches consensus or the
node binary. Nothing here modifies the running chain.

Prerequisites on the box:
- The public testnet node running with `-con_any_asset_fees=1` and an RPC
  endpoint (the committee runtime already provides this).
- A funded wallet loaded on that node (the founder treasury, `treasury-clean`)
  to fund issuance and pay the ordinary-asset fees openampd attaches.
- Go (matches the laptop toolchain; install under `~/dev-tools/go` if absent).

## 1. Clone/pull and build (on the box)

```
cd /root/sequentia
git clone https://github.com/GracedEternalKingCabbageMan/openamp.git   # first time
cd openamp && git pull
export PATH=$PATH:~/dev-tools/go/bin
go build -o openampd/openampd ./openampd/cmd/openampd
```

## 2. Secrets env file (box-only, never in git)

Write `/root/sequentia/openampd.env` (chmod 600):

```
OPENAMPD_RPC=http://127.0.0.1:<node-rpc-port>
OPENAMPD_RPCAUTH=<rpcuser>:<rpcpassword>       # or cookie:/root/.../.cookie
OPENAMPD_WALLET=treasury-clean
OPENAMPD_ISSUER_TOKEN=<long-random-token>       # gates the issuer API
OPENAMPD_FEE_ASSET=<display-hex of tSEQ or USDX>   # the asset openampd pays fees in
OPENAMPD_SIGNER=frost                           # policy-key backend; omit for `local`
OPENAMPD_DAMP_REGISTRY=/root/sequentia/openamp/opendamp/vectors/addresses.json
                                                # OpenDAMP CMR pinning file; omit to
                                                # answer 501 on every damp endpoint
OPENAMPD_ELECTRS_URL=http://127.0.0.1:3003      # explorer base URL (default shown);
                                                # prevout fallback without -txindex
```

The fee asset must be one the testnet producers accept (on their
`setfeeexchangerates` whitelist). tSEQ (the policy asset) always works.

The unit passes none of the last three as flags; `openampd` reads them from
the environment, so the env file is the only place they need to be set. The
public instance runs the FROST backend and has issued network-enforced assets,
which needs the first two.

## 3. Install and start the service

```
cp deploy/openampd.service /etc/systemd/system/openampd.service
systemctl daemon-reload
systemctl enable --now openampd
systemctl status openampd
journalctl -u openampd -f
```

## 4. Expose behind Caddy (optional public API)

openampd listens on 127.0.0.1:8722. To expose the wallet-facing endpoints at
`https://sequentiatestnet.com/openamp/`, add to the Caddyfile:

```
handle_path /openamp/* {
    reverse_proxy 127.0.0.1:8722
}
```

Then `systemctl reload caddy`. Consider leaving the issuer endpoints
(`/v1/issuer/*`) internal-only or firewalled; they are already token-gated.

## 5. Issue the demo restricted asset (BONDX)

Register an issuer account and a holder, then issue. Example against the local
API (token from the env file):

```
# register issuer + first holder (returns AIDs)
curl -s localhost:8722/v1/users -d '{"pubkeys":["<issuer-xonly-hex>"]}'
curl -s localhost:8722/v1/users -d '{"pubkeys":["<holder-xonly-hex>"]}'

# issue 1,000,000 BONDX into the holder's enclave (clawback ON by default)
curl -s localhost:8722/v1/issuer/assets \
  -H "Authorization: Bearer $OPENAMPD_ISSUER_TOKEN" \
  -d '{"name":"OpenAMP Demo Bond","ticker":"BONDX","precision":8,
       "atoms":100000000000000,"holder_aid":"<holder-aid>",
       "issuer_aid":"<issuer-aid>","burn_allowed":true,
       "rules":{"fee_convert_atoms":100}}'
```

The response returns the asset id, the contract JSON, and its hash. Publish
the contract to the registry so wallets can verify the asset-to-policy binding
(§4 of the [design doc](https://github.com/GracedEternalKingCabbageMan/Sequentia/blob/master/doc/sequentia/openamp-design.md)).
Transfers then go through `POST /v1/transfers` (fee convert/sponsor) or
`POST /v1/cosign` (self-paid), each requiring the holder's signature over the
returned sighashes; the full API and an end-to-end walkthrough are in the
top-level [README](../README.md).

## Per-transfer confidentiality

There are no confidential assets. Any transfer, burn, mint or reissue may pass
`confidential: true`; it blinds that transaction only and marks nothing about
the asset. openampd derives the enclave blinding keys itself and keeps them in
an `openampd-watch` node wallet, so the enclave side needs no node flag. The
funding wallet must be able to produce blinded change for its own fee-change
and token outputs, which every Sequentia wallet can do per call
(`-blindedaddresses=1` is not required). The end-to-end flow is proven in
`feature_openamp_confidential.py` (node repo).

## 6. Redeploy

`git pull && go build -o openampd/openampd ./openampd/cmd/openampd && systemctl restart openampd`.
State (registry, keys, transparency log) persists in
`/root/sequentia/openampd-data`.

## Note on keys (testnet demo vs production)

`-demoissuer` holds the issuer and policy keys server-side so the box can issue
and co-sign autonomously. That is appropriate ONLY for the testnet demo. A
production issuer keeps the issuer key offline and runs the policy key behind
a FROST threshold (or MPC/HSM) backend; the `PolicySigner` interface in
`openampd/internal/server/signer.go` is the seam for that. The FROST 2-of-3
backend ships (`-signer frost`, `OPENAMPD_SIGNER=frost`) and is what the
public instance runs; its members share one host today, so it guards against
a signing-path bug rather than host compromise — see "Trust model" in the
top-level README.
