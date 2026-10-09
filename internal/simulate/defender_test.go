package simulate

import "testing"

func TestParseDefenderEvents(t *testing.T) {
	detection := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1116</EventID></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Threat Name'>HackTool:Win32/Mimikatz.D</Data></EventData></Event>`
	other := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5007</EventID></System></Event>`

	evidence, ok := parseDefenderEvents(other + detection)
	if !ok || evidence != "Microsoft Defender: HackTool:Win32/Mimikatz.D" {
		t.Fatalf("parseDefenderEvents() = %q, %v", evidence, ok)
	}
	if _, ok := parseDefenderEvents(other); ok {
		t.Fatal("a non-detection event must not count as a block")
	}
	if _, ok := parseDefenderEvents(""); ok {
		t.Fatal("empty output must not count as a block")
	}
}
