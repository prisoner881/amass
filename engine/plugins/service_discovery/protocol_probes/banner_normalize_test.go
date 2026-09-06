package protocol_probes

import (
	"slices"
	"testing"
)

func TestBannerCandidates_OpenSSH(t *testing.T) {
	got := BannerCandidates("SSH-2.0-OpenSSH_9.6\r\n")
	if !slices.Contains(got, "SSH-2.0-OpenSSH_9.6") {
		t.Fatalf("expected trimmed wire banner first, got %#v", got)
	}
	if !slices.Contains(got, "OpenSSH_9.6") {
		t.Fatalf("expected Recog software field OpenSSH_9.6, got %#v", got)
	}
}

func TestBannerCandidates_OpenSSH74(t *testing.T) {
	got := BannerCandidates("SSH-2.0-OpenSSH_7.4\r")
	if !slices.Contains(got, "OpenSSH_7.4") {
		t.Fatalf("expected OpenSSH_7.4, got %#v", got)
	}
}

func TestBannerCandidates_DovecotPOP(t *testing.T) {
	got := BannerCandidates("+OK Dovecot ready.\r")
	if !slices.Contains(got, "Dovecot ready.") {
		t.Fatalf("expected greeting-stripped Dovecot field, got %#v", got)
	}
}

func TestBannerCandidates_DovecotIMAP(t *testing.T) {
	raw := "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.\r"
	got := BannerCandidates(raw)
	if !slices.Contains(got, "Dovecot ready.") {
		t.Fatalf("expected Dovecot ready. after * OK + CAPABILITY strip, got %#v", got)
	}
	if !slices.Contains(got, "[CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.") {
		t.Fatalf("expected CAPABILITY-preserving candidate (imap_banners.xml matches that form), got %#v", got)
	}
}

func TestBannerCandidates_FTPMultiline(t *testing.T) {
	raw := "220-Complete FTP server\r\n220 CompleteFTP v 22.2.2\r"
	got := BannerCandidates(raw)
	if !slices.Contains(got, "CompleteFTP v 22.2.2") {
		t.Fatalf("expected last-line greeting strip, got %#v", got)
	}
	if !slices.Contains(got, "Complete FTP server") {
		t.Fatalf("expected first-line greeting strip, got %#v", got)
	}
}

func TestBannerCandidates_Empty(t *testing.T) {
	if got := BannerCandidates(""); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
	if got := BannerCandidates("\r\n"); got != nil {
		t.Fatalf("expected nil for whitespace, got %#v", got)
	}
}
