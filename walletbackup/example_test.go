// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/walletbackup"
)

// Example demonstrates both recovery profiles using BIP32 test seeds and a
// real descriptor expression. All seeds here are deliberately public. The
// backup path m/100000'/0' is TEST-ONLY, not an assigned BIP path.
func Example() {
	// Setup: each device exports an account xpub and a backup public key.
	// This is the only time a device is asked for anything before
	// recovery.
	var participants []walletbackup.Participant
	var devices []*btcec.PrivateKey
	var keys []string
	for i := byte(1); i <= 3; i++ {
		master, err := hdkeychain.NewMaster(
			bytes.Repeat([]byte{i}, 32),
			&chaincfg.RegressionNetParams,
		)
		if err != nil {
			panic(err)
		}
		derive := func(path ...uint32) *hdkeychain.ExtendedKey {
			key := master
			for _, index := range path {
				key, err = key.Derive(
					hdkeychain.HardenedKeyStart + index,
				)
				if err != nil {
					panic(err)
				}
			}
			return key
		}
		backupPrivate, err := derive(100000, 0).ECPrivKey()
		if err != nil {
			panic(err)
		}
		masterPublic, err := master.ECPubKey()
		if err != nil {
			panic(err)
		}
		var participant walletbackup.Participant
		copy(
			participant.PublicKey[:],
			backupPrivate.PubKey().SerializeCompressed(),
		)
		copy(
			participant.Fingerprint[:],
			address.Hash160(masterPublic.SerializeCompressed())[:4],
		)
		participants = append(participants, participant)
		devices = append(devices, backupPrivate)
		account, err := derive(48, 1, 0, 2).Neuter()
		if err != nil {
			panic(err)
		}
		keys = append(keys, fmt.Sprintf(
			"[%x/48h/1h/0h/2h]%s/<0;1>/*", participant.Fingerprint,
			account,
		))
	}
	descriptor := "wsh(sortedmulti(2," + strings.Join(keys, ",") + "))"
	config := walletbackup.Config{
		Network: *chaincfg.RegressionNetParams.GenesisHash,
		Epoch:   450, Revision: 1,
	}
	if _, err := rand.Read(config.WalletID[:]); err != nil {
		panic(err)
	}
	height := uint32(450 * walletbackup.EpochBlocks)

	// Publication, single-device profile: the coordinator works from
	// public keys and the descriptor alone. No device is involved.
	config.Threshold = 1
	blob, err := walletbackup.Seal(config, participants, descriptor)
	if err != nil {
		panic(err)
	}

	// Recovery: any one device finds and opens the backup by itself.
	only, err := walletbackup.Open(config.Network, height, blob, devices[1])
	if err != nil {
		panic(err)
	}
	recovered, err := walletbackup.Recover(config.Network, blob, only)
	if err != nil {
		panic(err)
	}
	fmt.Println(
		"One device recovered the descriptor:", recovered == descriptor,
	)

	// Two-device profile: one device sees only the summary.
	config.Threshold = 2
	blob, err = walletbackup.Seal(config, participants, descriptor)
	if err != nil {
		panic(err)
	}
	first, err := walletbackup.Open(
		config.Network, height, blob, devices[0],
	)
	if err != nil {
		panic(err)
	}
	summary := first.Summary()
	fmt.Printf(
		"First device found a %d-of-%d recovery wallet\n",
		summary.Threshold, summary.Participants,
	)
	_, err = walletbackup.Recover(config.Network, blob, first)
	fmt.Println("One device needs another share:", errors.Is(
		err, walletbackup.ErrInsufficientShares,
	))
	second, err := walletbackup.Open(
		config.Network, height, blob, devices[2],
	)
	if err != nil {
		panic(err)
	}
	recovered, err = walletbackup.Recover(
		config.Network, blob, first, second,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(
		"First and third devices recovered the descriptor:",
		recovered == descriptor,
	)

	// Output:
	// One device recovered the descriptor: true
	// First device found a 2-of-3 recovery wallet
	// One device needs another share: true
	// First and third devices recovered the descriptor: true
}
