package adapters

import (
	"testing"

	"github.com/craftedsignal/cli/internal/simulate"
)

func TestAllObservablesUseValidSigmaFields(t *testing.T) {
	adapters := []simulate.BASAdapter{
		NewEmbedded(), NewAtomic(), NewMimikatz(), NewLsassy(), NewImpacket(),
	}
	for _, adapter := range adapters {
		techs, err := adapter.List(simulate.Filter{})
		if err != nil {
			t.Fatalf("adapter %s: List() failed: %v", adapter.Name(), err)
		}
		for _, tech := range techs {
			plan, err := adapter.Plan(tech.ID)
			if err != nil {
				t.Errorf("adapter %s technique %s: Plan() failed: %v", adapter.Name(), tech.ID, err)
				continue
			}
			if len(plan.Observables) == 0 {
				t.Errorf("adapter %s technique %s: no observables declared", adapter.Name(), tech.ID)
				continue
			}
			for _, obs := range plan.Observables {
				if !simulate.ValidSigmaFields[obs.Field] {
					t.Errorf("adapter %s technique %s: invalid Sigma field %q", adapter.Name(), tech.ID, obs.Field)
				}
				if obs.Value == "" {
					t.Errorf("adapter %s technique %s field %s: empty value", adapter.Name(), tech.ID, obs.Field)
				}
			}
		}
	}
}
