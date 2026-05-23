package socks5

import (
	"testing"
	"time"
)

func TestParsePassword(t *testing.T) {
	tests := []struct {
		name             string
		password         string
		wantRealPassword string
		wantSessionID    string
		wantDuration     time.Duration
	}{
		{
			name:             "password only",
			password:         "mypassword",
			wantRealPassword: "mypassword",
			wantSessionID:    "",
			wantDuration:     0,
		},
		{
			name:             "password with session",
			password:         "mypassword-abc123",
			wantRealPassword: "mypassword",
			wantSessionID:    "abc123",
			wantDuration:     0,
		},
		{
			name:             "password with session and seconds duration",
			password:         "mypassword-abc123-30s",
			wantRealPassword: "mypassword",
			wantSessionID:    "abc123",
			wantDuration:     30 * time.Second,
		},
		{
			name:             "password with session and minutes duration",
			password:         "mypassword-xyz456-5m",
			wantRealPassword: "mypassword",
			wantSessionID:    "xyz456",
			wantDuration:     5 * time.Minute,
		},
		{
			name:             "password with session and hours duration",
			password:         "mypassword-session1-2h",
			wantRealPassword: "mypassword",
			wantSessionID:    "session1",
			wantDuration:     2 * time.Hour,
		},
		{
			name:             "password with session and days duration",
			password:         "mypassword-session2-1d",
			wantRealPassword: "mypassword",
			wantSessionID:    "session2",
			wantDuration:     24 * time.Hour,
		},
		{
			name:             "session contains hyphens",
			password:         "mypassword-my-long-session-id-1h",
			wantRealPassword: "mypassword",
			wantSessionID:    "my-long-session-id",
			wantDuration:     1 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRealPassword, gotSessionID, gotDuration := parsePassword(tt.password)

			if gotRealPassword != tt.wantRealPassword {
				t.Errorf("parsePassword() realPassword = %v, want %v", gotRealPassword, tt.wantRealPassword)
			}
			if gotSessionID != tt.wantSessionID {
				t.Errorf("parsePassword() sessionID = %v, want %v", gotSessionID, tt.wantSessionID)
			}
			if gotDuration != tt.wantDuration {
				t.Errorf("parsePassword() duration = %v, want %v", gotDuration, tt.wantDuration)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:    "seconds",
			input:   "30s",
			want:    30 * time.Second,
			wantErr: false,
		},
		{
			name:    "minutes",
			input:   "5m",
			want:    5 * time.Minute,
			wantErr: false,
		},
		{
			name:    "hours",
			input:   "2h",
			want:    2 * time.Hour,
			wantErr: false,
		},
		{
			name:    "days",
			input:   "1d",
			want:    24 * time.Hour,
			wantErr: false,
		},
		{
			name:    "multiple days",
			input:   "7d",
			want:    7 * 24 * time.Hour,
			wantErr: false,
		},
		{
			name:    "invalid format",
			input:   "abc",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
