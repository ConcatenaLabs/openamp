// openampd is the OpenAMP policy server for Sequentia: registration,
// policy-checked co-signing of restricted-asset transfers, hosted issuance,
// fee conversion, freezes, clawback, reports, and a transparency log.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
	"github.com/ConcatenaLabs/openamp/openampd/internal/server"
	_ "github.com/ConcatenaLabs/openamp/openampd/internal/server/frostsigner" // registers -signer=frost
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

func main() {
	var (
		listen      = flag.String("listen", "127.0.0.1:8722", "HTTP listen address")
		datadir     = flag.String("datadir", defaultDatadir(), "state directory")
		rpcURL      = flag.String("rpc", "http://127.0.0.1:18776", "Sequentia node (sequentiad) RPC URL")
		rpcAuth     = flag.String("rpcauth", "", "user:pass or cookie:<path>")
		rpcWallet   = flag.String("rpcwallet", "", "wallet name (appended as /wallet/<name>)")
		issuerToken = flag.String("issuertoken", "", "bearer token for issuer endpoints")
		feeAsset    = flag.String("feeasset", os.Getenv("OPENAMPD_FEE_ASSET"), "display hex of the one asset the server pays fees in; the node must accept it for fees (default: none, each transaction's fee asset follows the wallet rule)")
		feeSats     = flag.Uint64("feesats", 1000, "the fee of each server-funded transaction, valued in the node's reference unit (atoms at a rate of 1e8) and paid in its fee asset at the node's rate")
		demoIssuer  = flag.Bool("demoissuer", false, "hold issuer keys server-side (testnet demo only)")
		signerName  = flag.String("signer", envOr("OPENAMPD_SIGNER", "local"), "policy-key backend: local (one key per asset) or frost (2-of-3 threshold)")
		electrsURL  = flag.String("electrs", envOr("OPENAMPD_ELECTRS_URL", "http://127.0.0.1:3003"), "explorer (electrs) base URL; prevout fallback when the node lacks -txindex")
		dampReg     = flag.String("dampregistry", os.Getenv("OPENAMPD_DAMP_REGISTRY"), "path to the OpenDAMP CMR pinning file (`opendamp registry` output, or vectors/addresses.json in the opendamp repository); unset disables network enforcement")
		follow      = flag.Duration("follow", 2*time.Second, "chain follower poll interval")
		tokenTool   = flag.String("tokentool", os.Getenv("OPENAMPD_TOKEN_TOOL"), "path to sequentia-contracts' token-covenants tool, which builds the supply cap every reissuance token is held in; unset, nothing can be issued or minted")
		capColdKey  = flag.String("capcoldkey", os.Getenv("OPENAMPD_CAP_COLD_KEY"), "default cold key (x-only hex) of a new supply cap: the key, kept off this server, that can replace its operator key")
		capOpKey    = flag.String("capoperatorkey", "", "this server's supply-cap operator key file (default <datadir>/cap-operator.key, made on first start)")
	)
	flag.Parse()

	if *rpcAuth == "" {
		log.Fatal("-rpcauth is required (user:pass or cookie:<path>)")
	}
	node, err := rpc.New(*rpcURL, *rpcAuth)
	if err != nil {
		log.Fatal(err)
	}
	// Scope the wallet client whenever -rpcwallet is passed at all (even ""),
	// so the demo wallet stays addressable once the blinding watch wallet
	// loads alongside it and makes unscoped wallet RPCs ambiguous. An empty
	// name scopes to the node's default wallet via /wallet/.
	walletURL := *rpcURL
	rpcWalletSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "rpcwallet" {
			rpcWalletSet = true
		}
	})
	if rpcWalletSet {
		walletURL = *rpcURL + "/wallet/" + *rpcWallet
	}
	wallet, err := rpc.New(walletURL, *rpcAuth)
	if err != nil {
		log.Fatal(err)
	}

	// The fee asset follows the wallet rule per transaction (feeasset.go in
	// the server package); an operator's -feeasset must be one the node
	// accepts, or nothing could ever be funded.
	rates, err := server.FeeRates(node.Call)
	if err != nil {
		log.Fatalf("read the node's fee exchange rates: %v", err)
	}
	if *feeAsset != "" {
		*feeAsset = strings.ToLower(*feeAsset)
		if rates[*feeAsset] == 0 {
			log.Fatalf("-feeasset %s is not an asset this node accepts for fees (getfeeexchangerates); name one it accepts, or leave -feeasset unset so each transaction pays in the asset the wallet rule picks", *feeAsset)
		}
	} else if len(rates) == 0 {
		log.Printf("the node accepts no asset for fees now: every server-funded transaction is refused until it does")
	}
	st, err := store.Open(*datadir)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Listen: *listen, IssuerToken: *issuerToken,
		FeeAsset: *feeAsset, FeeSats: *feeSats, DemoIssuer: *demoIssuer,
		ElectrsURL: *electrsURL, Signer: *signerName, DampRegistry: *dampReg,
		TokenTool: *tokenTool, CapOperatorKeyFile: *capOpKey, CapColdKey: *capColdKey,
	}, st, node, wallet)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.RunFollower(ctx, *follow)

	if *tokenTool != "" {
		log.Printf("supply caps through %s", *tokenTool)
	} else {
		log.Printf("supply caps not configured (-tokentool): issuance and minting are refused")
	}
	if *dampReg != "" {
		log.Printf("network enforcement configured from %s", *dampReg)
	}
	feeLine := "each transaction's fee asset by the wallet rule"
	if *feeAsset != "" {
		feeLine = "fee asset " + *feeAsset
	}
	log.Printf("openampd listening on %s (%s, fee worth %d reference-unit atoms)", *listen, feeLine, *feeSats)
	if err := http.ListenAndServe(*listen, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

func defaultDatadir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".openampd"
	}
	return home + "/.openampd"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
