package protocol_probes

import "testing"

func TestClassifyPeek(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want ProtocolGuess
	}{
		{"empty input", nil, GuessSilent},
		{"zero-length slice", []byte{}, GuessSilent},
		{"real OpenSSH banner", []byte("SSH-2.0-OpenSSH_9.6\r\n"), GuessSSH},
		{"real Dropbear SSH banner", []byte("SSH-2.0-dropbear_2022.83\r\n"), GuessSSH},
		{"SMTP-style 220 banner", []byte("220 mail.example.com ESMTP Postfix\r\n"), GuessAmbiguousBanner},
		{"FTP-style 220 banner", []byte("220 (vsFTPd 3.0.5)\r\n"), GuessAmbiguousBanner},
		{"POP3-style banner", []byte("+OK Dovecot ready.\r\n"), GuessAmbiguousBanner},
		{"garbage binary data", []byte{0x16, 0x03, 0x01, 0x00, 0x01}, GuessAmbiguousBanner},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyPeek(c.data)
			if got != c.want {
				t.Errorf("ClassifyPeek(%q) = %v, want %v", c.data, got, c.want)
			}
		})
	}
}
