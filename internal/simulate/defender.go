package simulate

import (
	"encoding/xml"
	"strings"
)

type defenderEvent struct {
	System struct {
		EventID int `xml:"EventID"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// parseDefenderEvents returns block evidence from `wevtutil /f:xml` output,
// or false when the output holds no detection event.
func parseDefenderEvents(output string) (string, bool) {
	var doc struct {
		Events []defenderEvent `xml:"Event"`
	}
	if err := xml.Unmarshal([]byte("<Events>"+output+"</Events>"), &doc); err != nil {
		return "", false
	}
	for _, ev := range doc.Events {
		if ev.System.EventID != 1116 && ev.System.EventID != 1117 {
			continue
		}
		for _, d := range ev.Data {
			if d.Name == "Threat Name" && strings.TrimSpace(d.Value) != "" {
				return "Microsoft Defender: " + strings.TrimSpace(d.Value), true
			}
		}
		return "Microsoft Defender detection", true
	}
	return "", false
}
