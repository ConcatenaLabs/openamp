package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

const recentBlockWindow = 100

// RunFollower tracks the chain: it confirms transfer records, and on a reorg
// (which on Sequentia is a designed-for event whenever Bitcoin reorgs) it
// re-marks records above the fork point as unconfirmed so velocity and
// reporting reflect only the surviving chain.
func (s *Server) RunFollower(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.followTick(); err != nil {
				log.Printf("follower: %v", err)
			}
		}
	}
}

func (s *Server) followTick() error {
	tip, err := s.node.GetBlockCount()
	if err != nil {
		return err
	}
	var prevHeight int64
	var prevBlocks []string
	s.st.View(func(st *store.State) {
		prevHeight = st.Height
		prevBlocks = append([]string(nil), st.RecentBlocks...)
	})

	// Detect a fork: compare stored recent hashes against the current chain.
	forkAt := int64(-1) // height of the first mismatching stored block
	base := prevHeight - int64(len(prevBlocks)) + 1
	for i, stored := range prevBlocks {
		h := base + int64(i)
		if h < 0 || h > tip {
			continue
		}
		cur, err := s.node.GetBlockHash(h)
		if err != nil {
			return err
		}
		if cur != stored {
			forkAt = h
			break
		}
	}

	// Collect txids of blocks from the fork (or the previous tip) up to now.
	scanFrom := prevHeight + 1
	if forkAt >= 0 {
		scanFrom = forkAt
	}
	confirmed := map[string]int64{}
	// What each scanned block spent: an outpoint (txid:vout) to the spending
	// transaction, its height and the size of that input's witness.
	spends := map[string]blockSpend{}
	for h := scanFrom; h <= tip; h++ {
		hash, err := s.node.GetBlockHash(h)
		if err != nil {
			return err
		}
		var blk struct {
			Tx []struct {
				Txid string `json:"txid"`
				Vin  []struct {
					Txid        string   `json:"txid"`
					Vout        uint32   `json:"vout"`
					Txinwitness []string `json:"txinwitness"`
				} `json:"vin"`
			} `json:"tx"`
		}
		if err := s.node.Call(&blk, "getblock", hash, 2); err != nil {
			return err
		}
		for _, tx := range blk.Tx {
			confirmed[tx.Txid] = h
			for _, in := range tx.Vin {
				if in.Txid != "" {
					spends[fmt.Sprintf("%s:%d", in.Txid, in.Vout)] = blockSpend{txid: tx.Txid, height: h, witness: len(in.Txinwitness)}
				}
			}
		}
	}

	// New recent-hash window.
	start := tip - recentBlockWindow + 1
	if start < 0 {
		start = 0
	}
	var recent []string
	for h := start; h <= tip; h++ {
		hash, err := s.node.GetBlockHash(h)
		if err != nil {
			return err
		}
		recent = append(recent, hash)
	}

	return s.st.Update(func(st *store.State) error {
		st.Height = tip
		st.RecentBlocks = recent
		for i := range st.Transfers {
			followRecord(&st.Transfers[i], forkAt, confirmed, spends)
		}
		st.Transfers = pruneReleased(st.Transfers, tip)
		return nil
	})
}

// followRecord brings one record up to the chain: a fork at or below its
// height or its release makes it pending again, and the blocks scanned from
// the fork settle it once more.
func followRecord(rec *store.TransferRecord, forkAt int64, confirmed map[string]int64, spends map[string]blockSpend) {
	if forkAt >= 0 && rec.Height >= forkAt {
		rec.Height = -1
	}
	if forkAt >= 0 && rec.Released >= forkAt {
		rec.Released = 0
	}
	if h, ok := confirmed[rec.Txid]; ok {
		rec.Height, rec.Released = h, 0
	}
	settleBySpends(rec, spends)
	// Records written before inputs were kept get the expiry they would have
	// had (#49).
	if rec.Height < 0 && len(rec.Inputs) == 0 && rec.Expires == 0 {
		rec.Expires = time.Now().Add(pendingTTL).Unix()
	}
}

// pruneReleased drops released records once their release is deeper than any
// fork the follower can see (recentBlockWindow).
func pruneReleased(recs []store.TransferRecord, tip int64) []store.TransferRecord {
	kept := recs[:0]
	for _, rec := range recs {
		if rec.Released > 0 && rec.Released <= tip-recentBlockWindow {
			continue
		}
		kept = append(kept, rec)
	}
	return kept
}

type blockSpend struct {
	txid    string
	height  int64
	witness int // items in the spending input's witness
}

// htlcClaimWitness is the size of an HTLC claim's witness: policy signature,
// buyer signature, secret, leaf and control block. A refund has two items, a
// claw four.
const htlcClaimWitness = 5

// settleBySpends reads what the newly scanned blocks did to an unconfirmed
// record's inputs.
//   - An HTLC claim record: the HTLC's outpoint spent by a claim is that claim,
//     counted at its height whichever co-signed claim it was (#65: a
//     superseded claim mined); spent by the refund or a claw, nothing moved
//     from the seller, and the record is released.
//   - Any other record: one of its inputs spent by another transaction makes
//     it impossible, and it is released. Until then it counts: a signature
//     never expires (#65).
//
// A released record keeps the height of the spend that released it, so a
// fork that undoes that spend makes it pending again (followRecord).
func settleBySpends(rec *store.TransferRecord, spends map[string]blockSpend) {
	if rec.Height >= 0 || rec.Released > 0 {
		return
	}
	if rec.Kind == "htlc-claim" {
		if sp, ok := spends[rec.ID]; ok {
			if sp.witness == htlcClaimWitness {
				rec.Height, rec.Txid = sp.height, sp.txid
			} else {
				rec.Released = sp.height
			}
		}
		return
	}
	for _, in := range rec.Inputs {
		if sp, ok := spends[in]; ok && sp.txid != rec.Txid {
			rec.Released = sp.height
			return
		}
	}
}
