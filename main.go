package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bitrise-io/go-utils/cmdex"
	"github.com/bitrise-io/go-utils/log"
	"github.com/bitrise-io/go-utils/pathutil"
)

// -----------------------
// --- Models
// -----------------------

// ConfigsModel ...
type ConfigsModel struct {
	CertificateURL         string
	CertificatePassphrase  string
	ProvisioningProfileURL string

	DefaultCertificateURL         string
	DefaultCertificatePassphrase  string
	DefaultProvisioningProfileURL string

	KeychainPath     string
	KeychainPassword string
}

func createConfigsModelFromEnvs() ConfigsModel {
	return ConfigsModel{
		CertificateURL:         os.Getenv("certificate_url"),
		CertificatePassphrase:  os.Getenv("certificate_passphrase"),
		ProvisioningProfileURL: os.Getenv("provisioning_profile_url"),

		DefaultCertificateURL:         os.Getenv("default_certificate_url"),
		DefaultCertificatePassphrase:  os.Getenv("default_certificate_passphrase"),
		DefaultProvisioningProfileURL: os.Getenv("default_provisioning_profile_url"),

		KeychainPath:     os.Getenv("keychain_path"),
		KeychainPassword: os.Getenv("keychain_password"),
	}
}

func (configs ConfigsModel) print() {
	fmt.Println()
	log.Info("Configs:")
	log.Detail(" - CertificateURL: %s", secureInput(configs.CertificateURL))
	log.Detail(" - CertificatePassphrase: %s", secureInput(configs.CertificatePassphrase))
	log.Detail(" - ProvisioningProfileURL: %s", secureInput(configs.ProvisioningProfileURL))

	log.Detail(" - DefaultCertificateURL: %s", secureInput(configs.DefaultCertificateURL))
	log.Detail(" - DefaultCertificatePassphrase: %s", secureInput(configs.DefaultCertificatePassphrase))
	log.Detail(" - DefaultProvisioningProfileURL: %s", secureInput(configs.DefaultProvisioningProfileURL))

	log.Detail(" - KeychainPath: %s", configs.KeychainPath)
	log.Detail(" - KeychainPassword: %s", secureInput(configs.KeychainPassword))
}

func (configs ConfigsModel) validate() error {
	if configs.KeychainPath == "" {
		return errors.New("No KeychainPath parameter specified!")
	}

	if configs.KeychainPassword == "" {
		return errors.New("No KeychainPassword parameter specified!")
	}

	return nil
}

//--------------------
// Functions
//--------------------

func exportEnvironmentWithEnvman(keyStr, valueStr string) error {
	envman := exec.Command("envman", "add", "--key", keyStr)
	envman.Stdin = strings.NewReader(valueStr)
	envman.Stdout = os.Stdout
	envman.Stderr = os.Stderr
	return envman.Run()
}

func downloadFile(destionationPath, URL string) error {
	url, err := url.Parse(URL)
	if err != nil {
		return err
	}

	scheme := url.Scheme

	tmpDstFilePath := ""
	if scheme != "file" {
		log.Detail("   Downloading (%s) to (%s)", secureInput(URL), destionationPath)

		tmpDir, err := pathutil.NormalizedOSTempDirPath("download")
		if err != nil {
			return err
		}

		tmpDst := path.Join(tmpDir, "tmp_file")
		tmpDstFile, err := os.Create(tmpDst)
		if err != nil {
			return err
		}
		defer tmpDstFile.Close()

		success := false
		var response *http.Response
		for i := 0; i < 3 && !success; i++ {
			if i > 0 {
				fmt.Println("-> Retrying...")
				time.Sleep(3 * time.Second)
			}

			response, err = http.Get(URL)
			if err != nil {
				log.Error(err.Error())
			} else {
				success = true
			}

			if response != nil {
				defer response.Body.Close()
			}
		}
		if !success {
			return err
		}

		_, err = io.Copy(tmpDstFile, response.Body)
		if err != nil {
			return err
		}

		tmpDstFilePath = tmpDstFile.Name()
	} else {
		log.Detail("   Moving (%s) to (%s)", secureInput(URL), destionationPath)
		tmpDstFilePath = strings.Replace(URL, scheme+"://", "", -1)
	}

	if out, err := runCommandAndReturnCombinedStdoutAndStderr("cp", tmpDstFilePath, destionationPath); err != nil {
		log.Detail("Move out: %s", out)
		return err
	}

	return nil
}

func runCommandAndReturnCombinedStdoutAndStderr(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	outBytes, err := cmd.CombinedOutput()
	outStr := string(outBytes)
	return strings.TrimSpace(outStr), err
}

func writeBytesToFileWithPermission(pth string, fileCont []byte, perm os.FileMode) error {
	if pth == "" {
		return errors.New("No path provided")
	}

	var file *os.File
	var err error
	if perm == 0 {
		file, err = os.Create(pth)
	} else {
		// same as os.Create, but with a specified permission
		//  the flags are copy-pasted from the official
		//  os.Create func: https://golang.org/src/os/file.go?s=7327:7366#L244
		file, err = os.OpenFile(pth, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	}
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Warn(" [!] Failed to close file:", err)
		}
	}()

	if _, err := file.Write(fileCont); err != nil {
		return err
	}

	return nil
}

func searchIphoneAndMacCreatificates(lines []string) []string {
	// "labl"<blob>="iPhone Distribution: XYZ (72SAXYZ)"
	certExp := regexp.MustCompile(`\"labl\"<blob>=\"(?P<profile>.*)\"`)

	// "labl"<blob>=0x6950686F6E6520446973747269627574696F6E3A20436C616E2056656E74757265205547202868616674756E6773626573636872EFBFBD6E6B7429202844564D455A524D50444D29  "iPhone Distribution: XYZ (xyz\357\277\275xyz) (XYZ)"
	longCertExp := regexp.MustCompile(`\"labl\"<blob>=.* \"(?P<profile>.*)\"`)

	certs := []string{}
	certFound := false

	for _, line := range lines {
		certRes := certExp.FindStringSubmatch(line)
		if certRes != nil {
			cert := certRes[1]
			certs = append(certs, cert)
			certFound = true
		}
		if !certFound {
			certRes := longCertExp.FindStringSubmatch(line)
			if certRes != nil {
				cert := certRes[1]
				certs = append(certs, cert)
			}
		}
		certFound = false
	}

	filteredCerts := []string{}
	for _, cert := range certs {
		if strings.HasPrefix(cert, "iPhone") || strings.HasPrefix(cert, "Mac") || strings.HasPrefix(cert, "3rd Party Mac") {
			filteredCerts = append(filteredCerts, cert)
		}
	}

	return filteredCerts
}

func searchFriendlyName(certStr string) string {
	// friendlyName: iPhone Distribution: XYZ (72SXYZ)
	certificateIdentityExp := regexp.MustCompile(`friendlyName: (?P<identity>.*)`)
	certificateIdentityRes := certificateIdentityExp.FindStringSubmatch(certStr)
	if certificateIdentityRes != nil {
		return certificateIdentityRes[1]
	}
	return ""
}

func certificateFriendlyName(certificatePath, certificatePassphrase string) (string, error) {
	out, err := runCommandAndReturnCombinedStdoutAndStderr("openssl", "pkcs12", "-info", "-nodes", "-in", certificatePath, "-passin", "pass:"+certificatePassphrase)
	if err != nil {
		return out, err
	}
	name := searchFriendlyName(out)
	return name, nil
}

func availableCertificates(keychainPath string) ([]string, error) {
	out, err := runCommandAndReturnCombinedStdoutAndStderr("security", "find-certificate", "-a", keychainPath)
	if err != nil {
		return []string{}, fmt.Errorf("Failed to list keys, err: %s", err)
	}

	outSplit := strings.Split(out, "\n")
	certs := searchIphoneAndMacCreatificates(outSplit)
	return certs, nil
}

func strip(str string) string {
	strippedStr := strings.TrimSpace(str)
	strippedStr = strings.Trim(strippedStr, "\"")
	return strippedStr
}

func addKeyChainToList(keyChainList []string, keyChain string) []string {
	keyChains := []string{}
	keyChainMap := map[string]bool{}

	keyChainList = append(keyChainList, keyChain)

	for _, aKeyChain := range keyChainList {
		found, _ := keyChainMap[aKeyChain]
		if !found {
			keyChains = append(keyChains, aKeyChain)
			keyChainMap[aKeyChain] = true
		}
	}

	return keyChains
}

func secureInput(str string) string {
	if str == "" {
		return ""
	}

	secureStr := func(s string, show int) string {
		runeCount := utf8.RuneCountInString(s)
		if runeCount < 6 || show == 0 {
			return strings.Repeat("*", 3)
		}
		if show*4 > runeCount {
			show = 1
		}

		sec := fmt.Sprintf("%s%s%s", s[0:show], strings.Repeat("*", 3), s[len(s)-show:len(s)])
		return sec
	}

	prefix := ""
	cont := str
	sec := secureStr(cont, 0)

	if strings.HasPrefix(str, "file://") {
		prefix = "file://"
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "http://www.") {
		prefix = "http://www."
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "https://www.") {
		prefix = "https://www."
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "http://") {
		prefix = "http://"
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	} else if strings.HasPrefix(str, "https://") {
		prefix = "https://"
		cont = strings.TrimPrefix(str, prefix)
		sec = secureStr(cont, 3)
	}

	return prefix + sec
}

func readProfileInfos(profilePth string) (string, error) {
	profileContent, err := cmdex.NewCommand("security", "cms", "-D", "-i", profilePth).RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Failed to print profile infos, out: %s, error: %s", profileContent, err)
	}

	lines := []string{}
	scanner := bufio.NewScanner(strings.NewReader(profileContent))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "<data>") {
			lines = append(lines, "REDACTED")
		} else {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(lines, "\n"), nil
}

//--------------------
// Main
//--------------------

func main() {
	configs := createConfigsModelFromEnvs()
	configs.print()
	if err := configs.validate(); err != nil {
		log.Error("Issue with input: %s", err)
		os.Exit(1)
	}
	fmt.Println()

	// Validate Certificates
	certificateURLPassphraseMap := map[string]string{}

	if configs.CertificateURL != "" {
		certificateURLs := strings.Split(configs.CertificateURL, "|")
		certificatePassphrases := strings.Split(configs.CertificatePassphrase, "|")

		if len(certificateURLs) != len(certificatePassphrases) {
			log.Error("Certificate url count: (%d), not equals to Certificate Passphrase count: (%d)", len(certificateURLs), len(certificatePassphrases))
			os.Exit(1)
		}

		for i := 0; i < len(certificateURLs); i++ {
			certificateURL := certificateURLs[i]
			certificatePassphrase := certificatePassphrases[i]

			certificateURLPassphraseMap[certificateURL] = certificatePassphrase
		}
	}

	if configs.DefaultCertificateURL != "" {
		log.Detail("Default Certificate given")
		certificateURLPassphraseMap[configs.DefaultCertificateURL] = configs.DefaultCertificatePassphrase
	}

	certificateCount := len(certificateURLPassphraseMap)
	log.Detail("Provided Certificate count: %d", certificateCount)

	if certificateCount == 0 {
		log.Error("No Certificate provided")
		os.Exit(1)
	}

	// Validate Provisioning Profiles
	provisioningProfileURLs := strings.Split(configs.ProvisioningProfileURL, "|")

	if configs.DefaultProvisioningProfileURL != "" {
		log.Detail("Default Provisioning Profile given")
		provisioningProfileURLs = append(provisioningProfileURLs, configs.DefaultProvisioningProfileURL)
	}

	profileCount := len(provisioningProfileURLs)
	log.Detail("Provided Provisioning Profile count: %d", profileCount)

	if profileCount == 0 {
		log.Error("No Provisioning Profile provided")
		os.Exit(1)
	}

	//
	// Init
	homeDir := os.Getenv("HOME")
	provisioningProfileDir := path.Join(homeDir, "Library/MobileDevice/Provisioning Profiles")
	if exist, err := pathutil.IsPathExists(provisioningProfileDir); err != nil {
		log.Error("Failed to check path (%s), err: %s", provisioningProfileDir, err)
		os.Exit(1)
	} else if !exist {
		if err := os.MkdirAll(provisioningProfileDir, 0777); err != nil {
			log.Error("Failed to create path (%s), err: %s", provisioningProfileDir, err)
			os.Exit(1)
		}
	}

	tempDir, err := pathutil.NormalizedOSTempDirPath("bitrise-cert-tmp")
	if err != nil {
		log.Error("Failed to create tmp directory, err: %s", err)
		os.Exit(1)
	}

	if exist, err := pathutil.IsPathExists(configs.KeychainPath); err != nil {
		log.Error("Failed to check path (%s), err: %s", configs.KeychainPath, err)
		os.Exit(1)
	} else if !exist {
		log.Info("Creating keychain: %s", configs.KeychainPath)

		if out, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "create-keychain", "-p", configs.KeychainPassword, configs.KeychainPath); err != nil {
			log.Error("Failed to create keychain, output: %s", out)
			log.Error("Failed to create keychain, err: %s", err)
			os.Exit(1)
		}
	} else {
		log.Detail("Keychain already exists, using it: %s", configs.KeychainPath)
	}

	//
	// Download certificate
	fmt.Println()
	log.Info("Downloading & installing Certificate(s)")

	certificatePassphraseMap := map[string]string{}
	idx := 0
	for certURL, pass := range certificateURLPassphraseMap {
		fmt.Println()
		log.Detail("=> Downloading certificate: %d/%d", idx+1, certificateCount)

		certPath := path.Join(tempDir, fmt.Sprintf("Certificate-%d.p12", idx))
		if err := downloadFile(certPath, certURL); err != nil {
			log.Error("Download failed, err: %s", err)
			os.Exit(1)
		}
		certificatePassphraseMap[certPath] = pass

		idx++
	}

	//
	// Install certificate
	fmt.Println()
	log.Detail("=> Installing downloaded certificate")

	for cert, pass := range certificatePassphraseMap {
		// Import items into a keychain.
		importOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "import", cert, "-k", configs.KeychainPath, "-P", pass, "-A")
		if err != nil {
			log.Error("Command failed, output: %s", importOut)
			log.Error("Command failed, err: %s", err)
			os.Exit(1)
		}
	}

	// Set keychain settings: Lock keychain when the system sleeps, Lock keychain after timeout interval, Timeout in seconds
	settingsOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "set-keychain-settings", "-lut", "72000", configs.KeychainPath)
	if err != nil {
		log.Error("Command failed, output: %s", settingsOut)
		log.Error("Command failed, err: %s", err)
		os.Exit(1)
	}

	// List keychains
	listKeychainsOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "list-keychains")
	if err != nil {
		log.Error("Command failed, output: %s", listKeychainsOut)
		log.Error("Command failed, err: %s", err)
		os.Exit(1)
	}

	keychainList := strings.Split(listKeychainsOut, "\n")
	strippedKeychainList := []string{}

	for _, keychain := range keychainList {
		strippedKeychain := strip(keychain)
		strippedKeychainList = append(strippedKeychainList, strippedKeychain)
	}

	strippedKeychainList = addKeyChainToList(strippedKeychainList, configs.KeychainPath)

	// Set keychain search path
	args := []string{"-v", "list-keychains", "-s"}
	args = append(args, strippedKeychainList...)

	listKeychainsOut, err = runCommandAndReturnCombinedStdoutAndStderr("security", args...)
	if err != nil {
		log.Error("Command failed, output: %s", listKeychainsOut)
		log.Error("Command failed, err: %s", err)
		os.Exit(1)
	}

	// Set the default keychain
	defaultKeychainOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "default-keychain", "-s", configs.KeychainPath)
	if err != nil {
		log.Error("Command failed, output: %s", defaultKeychainOut)
		log.Error("Command failed, err: %s", err)
		os.Exit(1)
	}

	// Unlock the specified keychain
	unlockOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "unlock-keychain", "-p", configs.KeychainPassword, configs.KeychainPath)
	if err != nil {
		log.Error("Command failed, output: %s", unlockOut)
		log.Error("Command failed, err: %s", err)
		os.Exit(1)
	}

	for cert, pass := range certificatePassphraseMap {
		certificateIdentity, err := certificateFriendlyName(cert, pass)
		if err != nil {
			log.Error("Failed to get cert identity, output: %s", certificateIdentity)
			log.Error("Failed to get cert identity, err: %s", err)
			os.Exit(1)
		}
		if certificateIdentity == "" {
			log.Error("Failed to get cert identity")
			os.Exit(1)
		}

		log.Done("   Installed certificate: %s", certificateIdentity)
	}

	certs, err := availableCertificates(configs.KeychainPath)
	if err != nil {
		log.Error("Failed to get certificate list, err:%s", err)
		os.Exit(1)
	}
	if len(certs) == 0 {
		log.Error("Failed to import certificate, no certificates found")
		os.Exit(1)
	}

	fmt.Println()
	log.Info("Available certificates:")
	fmt.Println("-----------------------")
	for _, cert := range certs {
		log.Detail(" * %s", cert)
	}

	//
	// Install provisioning profiles
	// NOTE: the URL can be a pipe (|) separated list of Provisioning Profile URLs
	fmt.Println()
	log.Info("Downloading & installing Provisioning Profile(s)")

	for idx, profileURL := range provisioningProfileURLs {
		fmt.Println()
		log.Detail("=> Downloading provisioning profile: %d/%d", idx+1, profileCount)

		provisioningProfileExt := "provisionprofile"
		if !strings.Contains(profileURL, "."+provisioningProfileExt) {
			provisioningProfileExt = "mobileprovision"
		}

		tmpPath := path.Join(tempDir, fmt.Sprintf("profile-%d.%s", idx, provisioningProfileExt))
		if err := downloadFile(tmpPath, profileURL); err != nil {
			log.Error("Download failed, err: %s", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("=> Installing provisioning profile")
		out, err := runCommandAndReturnCombinedStdoutAndStderr("/usr/bin/security", "cms", "-D", "-i", tmpPath)
		if err != nil {
			log.Error("Command failed, output: %s", out)
			log.Error("Command failed, err: %s", err)
			os.Exit(1)
		}

		tmpProvProfilePth := path.Join(tempDir, "prov")
		writeBytesToFileWithPermission(tmpProvProfilePth, []byte(out), 0)

		profile, err := readProfileInfos(tmpPath)
		if err != nil {
			log.Error("Failed to read profile infos, err: %s", err)
			os.Exit(1)
		}

		fmt.Println()
		log.Info("Profile Infos:")
		log.Detail("%s", profile)
		fmt.Println()

		profileUUID, err := runCommandAndReturnCombinedStdoutAndStderr("/usr/libexec/PlistBuddy", "-c", "Print UUID", tmpProvProfilePth)
		if err != nil {
			log.Error("Command failed, output: %s", profileUUID)
			log.Error("Command failed, err: %s", err)
			os.Exit(1)
		}

		log.Done("   Installed Profile UUID: %s", profileUUID)
		profileFinalPth := path.Join(provisioningProfileDir, profileUUID+"."+provisioningProfileExt)

		log.Detail("   Moving it to: %s", profileFinalPth)

		if out, err := runCommandAndReturnCombinedStdoutAndStderr("cp", tmpPath, profileFinalPth); err != nil {
			log.Error("Command failed, output: %s", out)
			log.Error("Command failed, err: %s", err)
			os.Exit(1)
		}
	}
}
