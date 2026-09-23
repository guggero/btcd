package descriptors

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

// TestDerivedInfoVectors compares metadata with the existing independently
// differential-tested spending corpus, without constructing expected scripts.
func TestDerivedInfoVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/derived_info.json")
	require.NoError(t, err)
	var vectors []struct {
		ID              string   `json:"id"`
		Descriptor      string   `json:"descriptor"`
		MultipathIndex  uint32   `json:"multipath_index"`
		DerivationIndex uint32   `json:"derivation_index"`
		ScriptPubKey    string   `json:"script_pubkey"`
		Witness         []string `json:"witness"`
		ScriptSig       string   `json:"script_sig"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	for _, vector := range vectors {
		t.Run(vector.ID, func(t *testing.T) {
			d, err := NewDescriptor(vector.Descriptor)
			require.NoError(t, err)
			info, err := d.DerivedInfoAt(
				vector.MultipathIndex, vector.DerivationIndex,
			)
			require.NoError(t, err)
			require.Equal(
				t, vector.ScriptPubKey,
				hex.EncodeToString(info.ScriptPubKey),
			)

			// Witness and redeem scripts already appear in the
			// portable completion. A nested witness program is the
			// last scriptSig push.
			if len(info.WitnessScript) != 0 {
				require.Equal(
					t,
					vector.Witness[len(vector.Witness)-1],
					hex.EncodeToString(info.WitnessScript),
				)
			}
			if len(info.RedeemScript) != 0 {
				scriptSig, err := hex.DecodeString(
					vector.ScriptSig,
				)
				require.NoError(t, err)
				pushes, err := txscript.PushedData(scriptSig)
				require.NoError(t, err)
				require.Equal(
					t, pushes[len(pushes)-1],
					info.RedeemScript,
				)
			}
			if strings.HasPrefix(vector.ID, "tr-tree-leaf-") {
				require.Len(t, info.TaprootLeaves, 3)
				leafIndex := int(
					vector.ID[len(vector.ID)-1] - '0',
				)
				leaf := info.TaprootLeaves[leafIndex]
				require.Equal(
					t, vector.Witness[1],
					hex.EncodeToString(leaf.Script),
				)
				require.Equal(
					t, vector.Witness[2],
					hex.EncodeToString(leaf.ControlBlock),
				)
				for _, leaf := range info.TaprootLeaves {
					control, err := txscript.ParseControlBlock(leaf.ControlBlock)
					require.NoError(t, err)
					require.NoError(
						t,
						txscript.VerifyTaprootLeafCommitment(control, info.ScriptPubKey[2:], leaf.Script),
					)
					require.Len(t, leaf.KeyPositions, 1)
				}
			}

			// A caller may edit its result without corrupting the
			// descriptor or another export, including nested proof
			// and key slices.
			again, err := d.DerivedInfoAt(
				vector.MultipathIndex, vector.DerivationIndex,
			)
			require.NoError(t, err)
			info.ScriptPubKey[0] ^= 1
			for i := range info.Keys {
				info.Keys[i].PubKey[0] ^= 1
			}
			for i := range info.TaprootLeaves {
				info.TaprootLeaves[i].ControlBlock[0] ^= 1
			}
			fresh, err := d.DerivedInfoAt(
				vector.MultipathIndex, vector.DerivationIndex,
			)
			require.NoError(t, err)
			require.Equal(t, again, fresh)
		})
	}
}
