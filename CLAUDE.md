# OpenAMP

`openampd`: a Go daemon that issues and polices issuer-governed restricted assets on Sequentia,
a self-hostable equivalent of Blockstream's AMP2. It requires **zero consensus changes** — it
talks to an ordinary Sequentia node (`sequentiad`) over JSON-RPC, and enforcement lives in
taproot script plus the policy server's signature.

`README.md` is the reference for the REST API, the trust model and the flag table. Read it
before changing behaviour; this file covers only what the README does not.

Node and consensus conventions live in the
[`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) repo.

## Build, test, run

Go 1.26+. Dependencies are vendored under `vendor/`, so builds work offline.

```sh
go build ./...
go test ./...
go build -o openampd/openampd ./openampd/cmd/openampd
```

There is no CI. `go build ./... && go test ./...` before every PR is the whole gate, plus
`e2e/supply_cap.py` (a real node and openampd; its docstring has the command) for a change to
issuance, minting or the supply cap, and `e2e/verifier_token.py` for a change to network-enforced
issuance or the verifier asset's token, `e2e/damp_two_phase.py` for a change to a snapshot or
derive document, `e2e/damp_contracts.py` for a change to a policy's list of contract templates, and
`e2e/fee_asset.py` for a change to how a fee is funded.

Deployment: `deploy/DEPLOY.md` plus the systemd units in `deploy/`. The server pulls this repo
from GitHub and builds there — never edit source on the server, never copy binaries onto it.

## Layout

| Path | What |
|---|---|
| `openampd/cmd/openampd/` | the daemon |
| `openampd/cmd/keygen`, `cmd/signer` | demo client helpers |
| `openampd/internal/server/` | HTTP API, policy engine, issuance, transfers, clawback, pledges, snapshots, chain follower |
| `openampd/internal/server/frostsigner/` | the FROST 2-of-3 policy-key backend (DKG, `Member`/`Transport` seam) |
| `openampd/internal/damp/` | OpenDAMP policy commitment, dmt-v1 tree, snapshot documents |
| `openampd/internal/elements/` | minimal Elements tx codec, taproot, sighash — golden-vectored |
| `openampd/internal/fastmerkle/` | issuance entropy and asset/token id derivation |
| `openampd/docs/` | design notes (blinding-key rotation, M2 snapshot service) |
| `e2e/supply_cap.py` | the supply cap end to end: a real openampd and node, a mint over the cap refused in a block |
| `e2e/fee_asset.py` | the fee rule end to end: no `-feeasset`, each fee paid in the asset whose largest coin covers the most fees, a node accepting nothing refused, a `-feeasset` the node does not accept refused at start |
| `e2e/damp_two_phase.py` | the README's two-phase issuance and policy update of a network-enforced asset, run as written: every document openampd returns goes to `opendamp` unchanged |
| `e2e/damp_contracts.py` | a policy's contract templates end to end: openampd lists SeqDEX's guarded order, opendamp derives and builds from the published document, the asset enters an order and a fill carries it to another whitelisted holder, and taking the template off the list stops the next fill |
| `e2e/verifier_token.py` | a network-enforced asset's verifier-asset token end to end: issued into its covenant, a halt that records, a resume, a transfer after it |
| `openampd/testdata/opendamp-contracts.json` | a pinned copy of opendamp's `vectors/contracts.json`, the same example policy listing the guarded order; it pins the contract-list commitment and the `pi` it gives, so copy it again when opendamp's template table changes, together with `damp.Whitelistable` |
| `openampd/testdata/opendamp-addresses.json` | a pinned copy of `vectors/addresses.json` from the [`opendamp`](https://github.com/ConcatenaLabs/opendamp) repository, which holds the covenants; the Go mirror tests check against it, so copy it again whenever opendamp's programs change |
| `spec/` | frozen formats (contract v1), venue/wallet integration spec |
| `tools/gen_vectors.py` | golden-vector generator |

## Things that are expensive to get wrong

- **The golden vectors are the proof that the hand-rolled Elements primitives are byte-exact.**
  If a change to `openampd/internal/elements` breaks them, regenerate or extend the vectors
  against the node repo's functional-test framework — never weaken or delete the test.

  ```sh
  PYTHONPATH=$SEQ_REPO/test/functional python3 tools/gen_vectors.py \
    > openampd/internal/elements/testdata/vectors.json
  go test ./openampd/internal/elements
  ```

- **Precision 0 is a real value, not "unset".** Integer-only restricted assets exist, so any code
  path handling `precision` has to distinguish an explicit `0` from an absent field. This was
  fixed once; do not reintroduce a zero-check that silently substitutes a default.
- **The asset id commits to the policy key**, via the issuance contract JSON hashed into the
  issuance entropy. Changing the contract shape changes every derived asset id. `spec/contract-v1.md`
  is frozen; pre-freeze assets on the live testnet carry legacy fields and must be verified as-is,
  because the hash commits to the exact bytes.
- **No asset pays this server's fees by default.** Every server-funded transaction picks its
  fee asset by the wallet rule in `openampd/internal/server/feeasset.go`, from what the node
  accepts now; `-feeasset` is an operator's pin, refused unless the node accepts it. Never add a
  fallback to the policy asset or to any other: on a node that does not accept it, a fallback is
  a transaction that is never mined, and anywhere else it is a privilege.
- **A restricted asset must never appear in a fee output.** The policy server refuses to co-sign
  such a transaction. That rule is what stops a restricted asset being swept into a block
  producer's coinbase; do not relax it for convenience.
- **`PolicySigner` in `openampd/internal/server/signer.go` is a deliberate seam.** Two backends
  are committed behind it: `local` (default; one software key per asset) and `frost` (2-of-3
  threshold, DKG-generated, selected with `-signer frost`). Keep new signing code behind the
  interface.
- **Reorg awareness is not optional.** Sequentia reorganises whenever Bitcoin reorganises, so the
  chain follower re-marks transfer records above a fork point as unconfirmed. Velocity accounting
  and ownership reports depend on it.
- **The server never holds a reissuance token.** Every token goes into a supply cap in the
  issuance transaction itself (`supplycap.go`), and every mint goes through the covenant via
  the `token-covenants` tool. Do not add a path that pays a token to the wallet or mints from
  one; a token in the wallet is unlimited mint authority for whoever holds that wallet's key.
  A network-enforced asset's verifier-asset token goes into its own covenant
  (`verifiertoken.go`) the same way: from the wallet it could mint the verifier asset anywhere,
  which bypasses the policy of every holder.
- **`-demoissuer` holds issuer keys server-side.** It is a testnet demo flag. A production issuer
  keeps that key offline.

## Working in this repo

- **Repository is public.** RPC credentials, issuer tokens and keys never belong in it. The
  daemon's key file lives in its data directory at mode 0600, outside the repo.
- **Commit author:**
  `GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`
- **Always open a pull request, then merge it yourself immediately.** The PR exists so the change
  and its reasoning are recorded, not because anyone is waiting to review it. There is no review
  process. If you are ever told to leave one specific PR open, that applies to that PR only and
  never becomes the default.
- PRs go against `main`, which is the remote default.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
