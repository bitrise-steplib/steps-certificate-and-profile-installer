package main

import (
	"testing"
)

const friendlyName = "iPhone Distribution: XYZ (xyz) (XYZ)"

const certValid = `MAC Iteration 1
MAC verified OK
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
Certificate bag
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
Bag Attributes
    friendlyName: iPhone Distribution: XYZ (xyz) (XYZ)
    localKeyID: 24 15
subject=/UID=XYZ/CN=iPhone Distribution: XYZ (xyz\xEF\xBF\xBDnkt) (XYZ)/OU=XYZ/O=XYZ (xyz\xEF\xBF\xBDnkt)/C=US
issuer=/C=US/O=Apple Inc./OU=Apple Worldwide Developer Relations/CN=Apple Worldwide Developer Relations Certification Authority
-----BEGIN CERTIFICATE-----
MIIFzzCCBLegAwIBAgIIMqtXAv51l80wDQYJKoZIhvcNAQEFBQAwgZYxCzAJBgNV
-----END CERTIFICATE-----
Bag Attributes
    friendlyName: DAA5EB07
    localKeyID: 24 15
Key Attributes: <No Attributes>
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA1KmLAKXfDg8YJFNb72nqkmexLiK8UC3Fqq5y0k9omfMx35yA
-----END RSA PRIVATE KEY-----
`

const certInvalid = `
MAC Iteration 1
MAC verified OK
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
Certificate bag
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
Bag Attributes
    localKeyID: 24 15
subject=/UID=XYZ/CN=iPhone Distribution: XYZ (xyz\xEF\xBF\xBDnkt) (XYZ)/OU=XYZ/O=XYZ (xyz\xEF\xBF\xBDnkt)/C=US
issuer=/C=US/O=Apple Inc./OU=Apple Worldwide Developer Relations/CN=Apple Worldwide Developer Relations Certification Authority
-----BEGIN CERTIFICATE-----
MIIFzzCCBLegAwIBAgIIMqtXAv51l80wDQYJKoZIhvcNAQEFBQAwgZYxCzAJBgNV
-----END CERTIFICATE-----
Bag Attributes
    localKeyID: 24 15
Key Attributes: <No Attributes>
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA1KmLAKXfDg8YJFNb72nqkmexLiK8UC3Fqq5y0k9omfMx35yA
-----END RSA PRIVATE KEY-----
`

func TestSearchIphoneAndMacCreatificates(t *testing.T) {
	// "labl"<blob>=0x6950686F6E6520446973747269627574696F6E3A20436C616E2056656E74757265205547202868616674756E6773626573636872EFBFBD6E6B7429202844564D455A524D50444D29  "iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)"
	// "labl"<blob>="iPhone Distribution: XYZ (72SAXYZ)"

	expectedCertsArray := [][]string{
		[]string{`iPhone Distribution: XYZ (72SAXYZ)`},
		[]string{`iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)`},
		[]string{`iPhone Distribution: XYZ (72SAXYZ)`, `iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)`},
	}

	for idx, lines := range [][]string{
		[]string{`"labl"<blob>="iPhone Distribution: XYZ (72SAXYZ)"`},
		[]string{`"labl"<blob>=0x6950686F6E6520446973747269627574696F6E3A20436C616E2056656E74757265205547202868616674756E6773626573636872EFBFBD6E6B7429202844564D455A524D50444D29  "iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)"`},
		[]string{`"labl"<blob>="iPhone Distribution: XYZ (72SAXYZ)"`, `"labl"<blob>=0x6950686F6E6520446973747269627574696F6E3A20436C616E2056656E74757265205547202868616674756E6773626573636872EFBFBD6E6B7429202844564D455A524D50444D29  "iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)"`},
	} {
		gotCerts := searchIphoneAndMacCreatificates(lines)
		expectedCerts := expectedCertsArray[idx]
		for i, gotCert := range gotCerts {
			if gotCert != expectedCerts[i] {
				t.Fatalf("Expected cert (%s) - got (%s)", expectedCerts[i], gotCert)
			}
		}
	}
}

func TestSearchFriendlyName(t *testing.T) {
	expectedNames := []string{friendlyName, ""}

	for idx, lines := range []string{
		certValid,
		certInvalid,
	} {
		gotName := searchFriendlyName(lines)
		expectedName := expectedNames[idx]
		if gotName != expectedName {
			t.Fatalf("Expected cert (%s) - got (%s)", expectedName, gotName)
		}
	}
}

func TestStip(t *testing.T) {
	t.Log(`Nothing to strip`)
	{
		line := `/Library/Keychains/System.keychain`

		got := strip(line)
		expected := `/Library/Keychains/System.keychain`
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log(`Strip removes: (")`)
	{
		line := `"/Library/Keychains/System.keychain"`

		got := strip(line)
		expected := `/Library/Keychains/System.keychain`
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log(`Strip removes: (\t)`)
	{
		line := `    /Library/Keychains/System.keychain       `

		got := strip(line)
		expected := `/Library/Keychains/System.keychain`
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log(`Strip removes: (\n)`)
	{
		line := `

    /Library/Keychains/System.keychain

    `

		got := strip(line)
		expected := `/Library/Keychains/System.keychain`
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log(`Strip`)
	{
		line := `

                      "/Library/Keychains/System.keychain"

    `

		got := strip(line)
		expected := `/Library/Keychains/System.keychain`
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}
}

/*
func addKeyChainToList(keyChainList []string, keyChain string) []string {
	keyChainMap := map[string]bool{}

	for _, aKeyChain := range keyChainList {
		keyChainMap[aKeyChain] = true
	}
	keyChainMap[keyChain] = true

	keyChains := []string{}
	for aKeyChain := range keyChainMap {
		keyChains = append(keyChains, aKeyChain)
	}

	return keyChains
}
*/

func arrayEquals(a1, a2 []string) bool {
	if len(a1) != len(a2) {
		Printlnf("a1: %d - a2: %d", len(a1), len(a2))
		return false
	}

	for i, e1 := range a1 {
		e2 := a2[i]
		if e1 != e2 {
			Printlnf("e1: %d - e2: %d", e1, e2)
			return false
		}
	}

	return true
}

func TestAddKeyChainToList(t *testing.T) {
	t.Log()
	{
		list := []string{"a", "b", "c"}
		item := "d"

		expected := []string{"a", "b", "c", "d"}
		got := addKeyChainToList(list, item)
		if !arrayEquals(got, expected) {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log()
	{
		list := []string{"a", "b", "c"}
		item := "a"

		expected := []string{"a", "b", "c"}
		got := addKeyChainToList(list, item)
		if !arrayEquals(got, expected) {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log()
	{
		list := []string{"a", "a", "b"}
		item := "a"

		expected := []string{"a", "b"}
		got := addKeyChainToList(list, item)
		if !arrayEquals(got, expected) {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}
}
