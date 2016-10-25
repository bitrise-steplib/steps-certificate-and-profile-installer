package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const profileContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key>
	<string>bitrise wild card</string>
	<key>ApplicationIdentifierPrefix</key>
	<array>
	<string>12344DLTN7</string>
	</array>
	<key>CreationDate</key>
	<date>2016-09-21T13:34:31Z</date>
	<key>Platform</key>
	<array>
		<string>iOS</string>
	</array>
	<key>DeveloperCertificates</key>
	<array>
		<data>1235678QYJKoZIhvcNAQEFBQAwgZYxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwOTIxMTMyMDA2WhcNMTcwOTIxMTMyMDA2WjCBiDEaMBgGCgmSJomT8ixkAQEMCjlOUzQ0RExUTjcxNDAyBgNVBAMMK2lQaG9uZSBEaXN0cmlidXRpb246IFNvbWUgRHVkZSAoOU5TNDRETFRONykxEzARBgNVBAsMCjlOUzQ0RExUTjcxEjAQBgNVBAoMCVNvbWUgRHVkZTELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjg61WV4/gyWzmc5ZsM2GJsGWsCv/Eo15WvhtDWi0fLYV+NwRvqTodDan6+UIyvY9b1/yGxEXbXhqlzo1SwaL49ZslBDN/E8Nzu7//EJMBrHv3XYLUFKAs9AQw3pXg3QMlL5QP6MzPHwN/WK+CBWdBrIpCcAOwmPcdM1oHlHm0NVk6QhzyGMXpjFUdDEIwFy6p7RSJ+FPmD68ENNnbrMjq1Abbj2kkC9K8CFnP8jKNs1Csv66NyUfKwEohSYMojkPuuCI7ENtIzRwfnQABYAmwIeblO+7IEhj5ZubCTbIO2PYjlpDSL49kxbrw38Ck9403kxmFSpyg4wVPfaiYRSgtAgMBAAGjggHxMIIB7TAdBgNVHQ4EFgQUcW2flxz+ERv6viUu2FFRzvqDBN8wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSIJxcJqbYYYIvs67r2R1nFUlSjtzCCAQ8GA1UdIASCAQYwggECMIH/BgkqhkiG92NkBQEwgfEwgcMGCCsGAQUFBwICMIG2DIGzUmVsaWFuY2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1lcyBhY2NlcHRhbmNlIG9mIHRoZSB0aGVuIGFwcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5kIGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnRpZmljYXRpb24gcHJhY3RpY2Ugc3RhdGVtZW50cy4wKQYIKwYBBQUHAgEWHWh0dHA6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9kZXZlbG9wZXIuYXBwbGUuY29tL2NlcnRpZmljYXRpb25hdXRob3JpdHkvd3dkcmNhLmNybDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwEwYKKoZIhvdjZAYBBAEB/wQCBQAwDQYJKoZIhvcNAQEFBQADggEBAADrYN6yP/sDRGx3IFrVT4WDnvIu9cA9adZye6KlfzlECUaCs4Twx+d2LxJlgj0FEd+3fj+ri0uVgx8rB1J7lYR6Nc4ntY4yQUvIkZ7azp4bUfRMVvmH7GSnS5eIQSIreoBnBpbYOFiBdeop9u1Uh5BOP79o0dUfRFMxsWtKl+tlaJP8EwTteeXLUWfJu96OkcZeAYrZvzZ1iVPoXkntaXyTNuB6Uq7sW0UIbt89ti2/Bm7InZCMMp9bi/051AKKeGtDvD2ViDo9I9l9M3f8a7Qu/Hd8Z0YiZxSQYgWpkVSz6mNS/ZW44FAe+ga98HtNnA4PwYKBNotWVrFPGq95azo=</data>
	</array>
	<key>Entitlements</key>
	<dict>
		<key>keychain-access-groups</key>
		<array>
			<string>12344DLTN7.*</string>
		</array>
		<key>get-task-allow</key>
		<false/>
		<key>application-identifier</key>
		<string>12344DLTN7.com.bitrise.*</string>
		<key>com.apple.developer.team-identifier</key>
		<string>12344DLTN7</string>
	</dict>
	<key>ExpirationDate</key>
	<date>2017-09-21T13:20:06Z</date>
	<key>Name</key>
	<string>iOS Distribution bitrise wild card</string>
	<key>ProvisionedDevices</key>
	<array>
		<string>12343075ad9b298cb9a9f28555c49573d8bc322</string>
	</array>
	<key>TeamIdentifier</key>
	<array>
		<string>12344DLTN7</string>
	</array>
	<key>TeamName</key>
	<string>Bitrise</string>
	<key>TimeToLive</key>
	<integer>364</integer>
	<key>UUID</key>
	<string>12345-57d7-4183-85f8-9dc5710447dd</string>
	<key>Version</key>
	<integer>1</integer>
</dict>
</plist>`

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

func arrayEquals(a1, a2 []string) bool {
	if len(a1) != len(a2) {
		fmt.Printf("a1: %d - a2: %d\n", len(a1), len(a2))
		return false
	}

	for i, e1 := range a1 {
		e2 := a2[i]
		if e1 != e2 {
			fmt.Printf("e1: %s - e2: %s\n", e1, e2)
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

func TestSecureInput(t *testing.T) {
	t.Log("secure empty")
	{
		expected := ""
		got := secureInput("")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure SHORT (<6) password")
	{
		expected := "***"
		got := secureInput("test")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure (>6) password")
	{
		expected := "***"
		got := secureInput("asdfghjk")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure SHORT (<6) url")
	{
		expected := "http://***"
		got := secureInput("http://te.hu")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure url")
	{
		expected := "http://t***u"
		got := secureInput("http://test.hu")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure LONG url")
	{
		expected := "http://tes***.hu"
		got := secureInput("http://test/alpha/beta.hu")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure SHORT (<6) path")
	{
		expected := "file://***"
		got := secureInput("file://test")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure path")
	{
		expected := "file://t***a"
		got := secureInput("file://test/beta")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}

	t.Log("secure LONG path")
	{
		expected := "file://tes***eta"
		got := secureInput("file://test/apha/beta")
		if got != expected {
			t.Fatalf("Expected: (%s), got: (%s)", expected, got)
		}
	}
}

/*
func readProfileInfos(profileContent string) (string, error) {
	lines := []string{}
	isDeveloperCertificatesSection := false
	isProvisionedDevicesSection := false

	scanner := bufio.NewScanner(strings.NewReader(profileContent))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, developerCertificatesStartLine) {
			isDeveloperCertificatesSection = true
			lines = append(lines, line)
			continue
		}
		if isDeveloperCertificatesSection {
			if strings.Contains(line, developerCertificatesArrayEndLine) {
				isDeveloperCertificatesSection = false
				lines = append(lines, fmt.Sprintf("%s[REDACTED]", strings.Repeat(" ", 16)))
			}

			continue
		}

		if strings.Contains(line, provisionedDevicesStartLine) {
			isProvisionedDevicesSection = true
			lines = append(lines, line)
			continue
		}
		if isProvisionedDevicesSection {
			if strings.Contains(line, provisionedDevicesArrayEndLine) {
				isProvisionedDevicesSection = false
				lines = append(lines, fmt.Sprintf("%s[REDACTED]", strings.Repeat(" ", 16)))
			}

			continue
		}

		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("Failed to scan profile, error: %s", err)
	}

	return strings.Join(lines, "\n"), nil
}
*/

func TestPrintableProfileInfos(t *testing.T) {
	t.Log()
	{
		profileInfos, err := printableProfileInfos(profileContent)
		require.NoError(t, err)
		require.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key>
	<string>bitrise wild card</string>
	<key>ApplicationIdentifierPrefix</key>
	<array>
	<string>12344DLTN7</string>
	</array>
	<key>CreationDate</key>
	<date>2016-09-21T13:34:31Z</date>
	<key>Platform</key>
	<array>
		<string>iOS</string>
	</array>
	<key>DeveloperCertificates</key>
                [REDACTED]
	<key>Entitlements</key>
	<dict>
		<key>keychain-access-groups</key>
		<array>
			<string>12344DLTN7.*</string>
		</array>
		<key>get-task-allow</key>
		<false/>
		<key>application-identifier</key>
		<string>12344DLTN7.com.bitrise.*</string>
		<key>com.apple.developer.team-identifier</key>
		<string>12344DLTN7</string>
	</dict>
	<key>ExpirationDate</key>
	<date>2017-09-21T13:20:06Z</date>
	<key>Name</key>
	<string>iOS Distribution bitrise wild card</string>
	<key>ProvisionedDevices</key>
                [REDACTED]
	<key>TeamIdentifier</key>
	<array>
		<string>12344DLTN7</string>
	</array>
	<key>TeamName</key>
	<string>Bitrise</string>
	<key>TimeToLive</key>
	<integer>364</integer>
	<key>UUID</key>
	<string>12345-57d7-4183-85f8-9dc5710447dd</string>
	<key>Version</key>
	<integer>1</integer>
</dict>
</plist>`, profileInfos)
	}
}
