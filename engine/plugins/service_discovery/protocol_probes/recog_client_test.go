package protocol_probes

import (
	"strings"
	"testing"
)

func TestIdentifyBanner_OpenSSH(t *testing.T) {
	res := IdentifyBanner("SSH-2.0-OpenSSH_9.6\r\n", "ssh_banners.xml")
	if res.LoadError != nil {
		t.Fatalf("LoadFingerprints failed: %v", res.LoadError)
	}
	if len(res.MissingDBs) > 0 {
		t.Fatalf("ssh_banners.xml missing from embed: %v", res.MissingDBs)
	}
	if !res.Matched {
		t.Fatalf("expected OpenSSH match, candidates=%v", res.Candidates)
	}
	if !strings.Contains(strings.ToLower(res.Product), "openssh") {
		t.Fatalf("product=%q vendor=%q version=%q db=%q input=%q",
			res.Product, res.Vendor, res.Version, res.Database, res.Input)
	}
}

func TestIdentifyBanner_DovecotPOP(t *testing.T) {
	res := IdentifyBanner("+OK Dovecot ready.\r", "pop_banners.xml")
	if res.LoadError != nil {
		t.Fatalf("LoadFingerprints failed: %v", res.LoadError)
	}
	if len(res.MissingDBs) > 0 {
		t.Fatalf("pop_banners.xml missing from embed: %v", res.MissingDBs)
	}
	if !res.Matched {
		t.Fatalf("expected Dovecot POP match after +OK/CR strip, candidates=%v", res.Candidates)
	}
	if !strings.EqualFold(res.Product, "Dovecot") {
		t.Fatalf("product=%q vendor=%q db=%q input=%q",
			res.Product, res.Vendor, res.Database, res.Input)
	}
}

func TestIdentifyBanner_DovecotIMAP(t *testing.T) {
	raw := "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.\r"
	res := IdentifyBanner(raw, "imap_banners.xml")
	if res.LoadError != nil {
		t.Fatalf("LoadFingerprints failed: %v", res.LoadError)
	}
	if len(res.MissingDBs) > 0 {
		t.Fatalf("imap_banners.xml missing from embed: %v", res.MissingDBs)
	}
	if !res.Matched {
		t.Fatalf("expected Dovecot IMAP match after * OK strip, candidates=%v", res.Candidates)
	}
	if !strings.EqualFold(res.Product, "Dovecot") {
		t.Fatalf("product=%q vendor=%q db=%q input=%q",
			res.Product, res.Vendor, res.Database, res.Input)
	}
}

func TestIdentifyBanner_MissingDB(t *testing.T) {
	res := IdentifyBanner("SSH-2.0-OpenSSH_9.6\r\n", "does_not_exist.xml")
	if res.LoadError != nil {
		t.Fatalf("LoadFingerprints failed: %v", res.LoadError)
	}
	if res.Matched {
		t.Fatalf("matched a database that should not exist")
	}
	if len(res.MissingDBs) != 1 || res.MissingDBs[0] != "does_not_exist.xml" {
		t.Fatalf("MissingDBs=%v", res.MissingDBs)
	}
}

func TestIdentifyBanner_OpenSSH74(t *testing.T) {
	res := IdentifyBanner("SSH-2.0-OpenSSH_7.4\r", "ssh_banners.xml")
	if res.LoadError != nil {
		t.Fatalf("LoadFingerprints failed: %v", res.LoadError)
	}
	if len(res.MissingDBs) > 0 {
		t.Fatalf("ssh_banners.xml missing from embed: %v", res.MissingDBs)
	}
	if !res.Matched {
		t.Fatalf("expected OpenSSH 7.4 match, candidates=%v", res.Candidates)
	}
	if !strings.Contains(strings.ToLower(res.Product), "openssh") {
		t.Fatalf("product=%q vendor=%q version=%q input=%q",
			res.Product, res.Vendor, res.Version, res.Input)
	}
	if res.Input != "OpenSSH_7.4" {
		t.Fatalf("matched input=%q, want OpenSSH_7.4 (software field)", res.Input)
	}
}

func TestIdentifyBanner_CompleteFTPNoFingerprint(t *testing.T) {
	res := IdentifyBanner("SSH-2.0-CompleteFTP_22.1.1\r", "ssh_banners.xml")
	if res.LoadError != nil {
		t.Fatalf("LoadFingerprints failed: %v", res.LoadError)
	}
	if res.Matched {
		t.Fatalf("CompleteFTP is not in Recog; unexpected match product=%q", res.Product)
	}
}
