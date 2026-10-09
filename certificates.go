package main

import (
	"github.com/bitrise-io/go-xcode/certificateutil"
	"github.com/bitrise-io/go-xcode/profileutil"
)

// deduplicateCertificates drops certificates sharing their common name with another one,
// as Xcode selects identities by name and might pick one not included in the profile.
// Certificates included in a profile are always kept; if none is, the latest expiring valid one is kept.
// Same-named certificates kept because of profiles are returned as ambiguous. Input order is preserved.
func deduplicateCertificates(certificates []certificateutil.CertificateInfoModel, profiles []profileutil.ProvisioningProfileInfoModel) (kept, dropped, ambiguous []certificateutil.CertificateInfoModel) {
	profileCertFingerprints := map[string]bool{}
	for _, profile := range profiles {
		for _, cert := range profile.DeveloperCertificates {
			profileCertFingerprints[cert.SHA1Fingerprint] = true
		}
	}

	var unique []certificateutil.CertificateInfoModel
	seenFingerprints := map[string]bool{}
	for _, cert := range certificates {
		if seenFingerprints[cert.SHA1Fingerprint] {
			dropped = append(dropped, cert)
			continue
		}
		seenFingerprints[cert.SHA1Fingerprint] = true
		unique = append(unique, cert)
	}

	nameHasProfileCert := map[string]bool{}
	for _, cert := range unique {
		if profileCertFingerprints[cert.SHA1Fingerprint] {
			nameHasProfileCert[cert.CommonName] = true
		}
	}

	bestByName := map[string]int{}
	for i, cert := range unique {
		if nameHasProfileCert[cert.CommonName] {
			continue
		}
		best, ok := bestByName[cert.CommonName]
		if !ok || isPreferredCertificate(cert, unique[best]) {
			bestByName[cert.CommonName] = i
		}
	}

	keptProfileCertByName := map[string]bool{}
	for i, cert := range unique {
		if nameHasProfileCert[cert.CommonName] {
			if !profileCertFingerprints[cert.SHA1Fingerprint] {
				dropped = append(dropped, cert)
				continue
			}
			if keptProfileCertByName[cert.CommonName] {
				ambiguous = append(ambiguous, cert)
			}
			keptProfileCertByName[cert.CommonName] = true
			kept = append(kept, cert)
			continue
		}

		if bestByName[cert.CommonName] == i {
			kept = append(kept, cert)
		} else {
			dropped = append(dropped, cert)
		}
	}

	return kept, dropped, ambiguous
}

// isPreferredCertificate reports whether a should be installed instead of b: valid first, then later expiry.
func isPreferredCertificate(a, b certificateutil.CertificateInfoModel) bool {
	aValid, bValid := a.CheckValidity() == nil, b.CheckValidity() == nil
	if aValid != bValid {
		return aValid
	}

	return a.EndDate.After(b.EndDate)
}
