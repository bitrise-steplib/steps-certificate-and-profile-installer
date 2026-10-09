package main

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/bitrise-io/go-xcode/certificateutil"
	"github.com/bitrise-io/go-xcode/profileutil"
	"github.com/stretchr/testify/require"
)

func newCert(name, fingerprint string, endDate time.Time) certificateutil.CertificateInfoModel {
	startDate := endDate.AddDate(-1, 0, 0)
	return certificateutil.CertificateInfoModel{
		CommonName:      name,
		SHA1Fingerprint: fingerprint,
		StartDate:       startDate,
		EndDate:         endDate,
		Certificate:     x509.Certificate{NotBefore: startDate, NotAfter: endDate},
	}
}

func newProfile(certs ...certificateutil.CertificateInfoModel) profileutil.ProvisioningProfileInfoModel {
	return profileutil.ProvisioningProfileInfoModel{DeveloperCertificates: certs}
}

func TestDeduplicateCertificates(t *testing.T) {
	now := time.Now()
	devOlder := newCert("Apple Development: Bot (ABC)", "dev-older", now.AddDate(0, 6, 0))
	devNewer := newCert("Apple Development: Bot (ABC)", "dev-newer", now.AddDate(0, 7, 0))
	devExpired := newCert("Apple Development: Bot (ABC)", "dev-expired", now.AddDate(0, -1, 0))
	dist := newCert("Apple Distribution: Team (XYZ)", "dist", now.AddDate(1, 0, 0))

	tests := []struct {
		name          string
		certificates  []certificateutil.CertificateInfoModel
		profiles      []profileutil.ProvisioningProfileInfoModel
		wantKept      []certificateutil.CertificateInfoModel
		wantDropped   []certificateutil.CertificateInfoModel
		wantAmbiguous []certificateutil.CertificateInfoModel
	}{
		{
			name:         "no duplicates",
			certificates: []certificateutil.CertificateInfoModel{devOlder, dist},
			wantKept:     []certificateutil.CertificateInfoModel{devOlder, dist},
		},
		{
			name:         "prefers certificate included in a profile over later expiry",
			certificates: []certificateutil.CertificateInfoModel{devNewer, dist, devOlder},
			profiles:     []profileutil.ProvisioningProfileInfoModel{newProfile(devOlder, dist)},
			wantKept:     []certificateutil.CertificateInfoModel{dist, devOlder},
			wantDropped:  []certificateutil.CertificateInfoModel{devNewer},
		},
		{
			name:         "prefers later expiry when no profile includes either",
			certificates: []certificateutil.CertificateInfoModel{devOlder, devNewer, dist},
			wantKept:     []certificateutil.CertificateInfoModel{devNewer, dist},
			wantDropped:  []certificateutil.CertificateInfoModel{devOlder},
		},
		{
			name:          "keeps all certificates included in different profiles",
			certificates:  []certificateutil.CertificateInfoModel{devNewer, devOlder},
			profiles:      []profileutil.ProvisioningProfileInfoModel{newProfile(devOlder), newProfile(devNewer)},
			wantKept:      []certificateutil.CertificateInfoModel{devNewer, devOlder},
			wantAmbiguous: []certificateutil.CertificateInfoModel{devNewer, devOlder},
		},
		{
			name:          "keeps all certificates included in the same profile, drops the one not included",
			certificates:  []certificateutil.CertificateInfoModel{devExpired, devNewer, devOlder},
			profiles:      []profileutil.ProvisioningProfileInfoModel{newProfile(devOlder, devNewer)},
			wantKept:      []certificateutil.CertificateInfoModel{devNewer, devOlder},
			wantDropped:   []certificateutil.CertificateInfoModel{devExpired},
			wantAmbiguous: []certificateutil.CertificateInfoModel{devNewer, devOlder},
		},
		{
			name:         "prefers valid over expired",
			certificates: []certificateutil.CertificateInfoModel{devExpired, devOlder},
			wantKept:     []certificateutil.CertificateInfoModel{devOlder},
			wantDropped:  []certificateutil.CertificateInfoModel{devExpired},
		},
		{
			name:         "prefers expired certificate included in a profile",
			certificates: []certificateutil.CertificateInfoModel{devExpired, devOlder},
			profiles:     []profileutil.ProvisioningProfileInfoModel{newProfile(devExpired)},
			wantKept:     []certificateutil.CertificateInfoModel{devExpired},
			wantDropped:  []certificateutil.CertificateInfoModel{devOlder},
		},
		{
			name:         "same certificate provided twice",
			certificates: []certificateutil.CertificateInfoModel{dist, dist},
			wantKept:     []certificateutil.CertificateInfoModel{dist},
			wantDropped:  []certificateutil.CertificateInfoModel{dist},
		},
		{
			name:         "same certificate included in a profile provided twice",
			certificates: []certificateutil.CertificateInfoModel{dist, dist},
			profiles:     []profileutil.ProvisioningProfileInfoModel{newProfile(dist), newProfile(dist)},
			wantKept:     []certificateutil.CertificateInfoModel{dist},
			wantDropped:  []certificateutil.CertificateInfoModel{dist},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept, dropped, ambiguous := deduplicateCertificates(tt.certificates, tt.profiles)
			require.Equal(t, tt.wantKept, kept)
			require.Equal(t, tt.wantDropped, dropped)
			require.Equal(t, tt.wantAmbiguous, ambiguous)
		})
	}
}
