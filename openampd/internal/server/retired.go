package server

import "net/http"

// EnclaveRetired is the refusal every request for an asset's tree gets. A
// restricted asset (co-signed or network-enforced) is held, moved and traded
// on the chain only: in its holder's enclave, through a co-sign of this
// server, a swap HTLC, an asset-for-asset trade or a gated order.
const EnclaveRetired = "enclave-1 was retired: restricted assets stay on the chain"

// retiredRoutes answer 410 Gone with EnclaveRetired, so a client that still
// calls one gets a named refusal rather than a 404.
var retiredRoutes = []string{
	"POST /v1/tree/leaves/{salt}/exited",
	"POST /v1/issuer/tree",
	"POST /v1/issuer/tree/transfer",
	"POST /v1/issuer/tree/transfer/{id}/drop",
	"POST /v1/issuer/tree/clawback",
}

func handleRetired(w http.ResponseWriter, r *http.Request) {
	httpErr(w, http.StatusGone, "%s", EnclaveRetired)
}
