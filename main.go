package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bitrise-io/go-utils/command"
	"github.com/bitrise-io/go-utils/errorutil"
	"github.com/bitrise-io/go-utils/log"
	"github.com/bitrise-io/go-utils/pathutil"
	"github.com/bitrise-io/steps-certificate-and-profile-installer/certificateutil"
	"github.com/bitrise-io/steps-certificate-and-profile-installer/profileutil"
	version "github.com/hashicorp/go-version"
)

const (
	notValidParameterErrorMessage = "security: SecPolicySetValue: One or more parameters passed to a function were not valid."
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
	log.Infof("Configs:")
	log.Printf(" - CertificateURL: %s", secureInput(configs.CertificateURL))
	log.Printf(" - CertificatePassphrase: %s", secureInput(configs.CertificatePassphrase))
	log.Printf(" - ProvisioningProfileURL: %s", secureInput(configs.ProvisioningProfileURL))

	log.Printf(" - DefaultCertificateURL: %s", secureInput(configs.DefaultCertificateURL))
	log.Printf(" - DefaultCertificatePassphrase: %s", secureInput(configs.DefaultCertificatePassphrase))
	log.Printf(" - DefaultProvisioningProfileURL: %s", secureInput(configs.DefaultProvisioningProfileURL))

	log.Printf(" - KeychainPath: %s", configs.KeychainPath)
	log.Printf(" - KeychainPassword: %s", secureInput(configs.KeychainPassword))
}

func (configs ConfigsModel) validate() error {
	if configs.KeychainPath == "" {
		return errors.New("no KeychainPath parameter specified")
	}

	if configs.KeychainPassword == "" {
		return errors.New("no KeychainPassword parameter specified")
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
		tmpDir, err := pathutil.NormalizedOSTempDirPath("download")
		if err != nil {
			return err
		}

		tmpDst := path.Join(tmpDir, "tmp_file")
		tmpDstFile, err := os.Create(tmpDst)
		if err != nil {
			return err
		}
		defer func() {
			if err := tmpDstFile.Close(); err != nil {
				log.Errorf("Failed to close file (%s), error: %s", tmpDst, err)
			}
		}()

		success := false
		var response *http.Response
		for i := 0; i < 3 && !success; i++ {
			if i > 0 {
				fmt.Println("-> Retrying...")
				time.Sleep(3 * time.Second)
			}

			response, err = http.Get(URL)
			if err != nil {
				log.Errorf(err.Error())
			} else {
				success = true
			}

			if response != nil {
				defer func() {
					if err := response.Body.Close(); err != nil {
						log.Errorf("Failed to close response body, error: %s", err)
					}
				}()
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
		tmpDstFilePath = strings.Replace(URL, scheme+"://", "", -1)
	}

	if out, err := runCommandAndReturnCombinedStdoutAndStderr("cp", tmpDstFilePath, destionationPath); err != nil {
		log.Printf("Move out: %s", out)
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
			log.Warnf(" [!] Failed to close file:", err)
		}
	}()

	if _, err := file.Write(fileCont); err != nil {
		return err
	}

	return nil
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

//--------------------
// Main
//--------------------

func main() {
	configs := createConfigsModelFromEnvs()
	configs.print()
	if err := configs.validate(); err != nil {
		log.Errorf("Issue with input: %s", err)
		os.Exit(1)
	}
	fmt.Println()

	// Validate Certificates
	certificateURLPassphraseMap := map[string]string{}

	if configs.CertificateURL != "" {
		certificateURLs := []string{}
		for _, certURL := range strings.Split(configs.CertificateURL, "|") {
			if certURL != "" {
				certificateURLs = append(certificateURLs, certURL)
			}
		}

		certificatePassphrases := strings.Split(configs.CertificatePassphrase, "|")

		if len(certificateURLs) != len(certificatePassphrases) {
			log.Errorf("Certificate url count: (%d), not equals to Certificate Passphrase count: (%d)", len(certificateURLs), len(certificatePassphrases))
			os.Exit(1)
		}

		for i := 0; i < len(certificateURLs); i++ {
			certificateURL := certificateURLs[i]
			certificatePassphrase := certificatePassphrases[i]

			certificateURLPassphraseMap[certificateURL] = certificatePassphrase
		}
	}

	if configs.DefaultCertificateURL != "" {
		log.Printf("Default Certificate given")
		certificateURLPassphraseMap[configs.DefaultCertificateURL] = configs.DefaultCertificatePassphrase
	}

	certificateCount := len(certificateURLPassphraseMap)
	log.Printf("Provided Certificate count: %d", certificateCount)

	if certificateCount == 0 {
		log.Errorf("No Certificate provided")
		os.Exit(1)
	}

	// Validate Provisioning Profiles
	provisioningProfileURLs := []string{}
	for _, profileURL := range strings.Split(configs.ProvisioningProfileURL, "|") {
		if profileURL != "" {
			provisioningProfileURLs = append(provisioningProfileURLs, profileURL)
		}
	}

	if configs.DefaultProvisioningProfileURL != "" {
		log.Printf("Default Provisioning Profile given")
		provisioningProfileURLs = append(provisioningProfileURLs, configs.DefaultProvisioningProfileURL)
	}

	profileCount := len(provisioningProfileURLs)
	log.Printf("Provided Provisioning Profile count: %d", profileCount)

	if profileCount == 0 {
		log.Errorf("No Provisioning Profile provided")
		os.Exit(1)
	}

	//
	// Init
	homeDir := os.Getenv("HOME")
	provisioningProfileDir := path.Join(homeDir, "Library/MobileDevice/Provisioning Profiles")
	if exist, err := pathutil.IsPathExists(provisioningProfileDir); err != nil {
		log.Errorf("Failed to check path (%s), err: %s", provisioningProfileDir, err)
		os.Exit(1)
	} else if !exist {
		if err := os.MkdirAll(provisioningProfileDir, 0777); err != nil {
			log.Errorf("Failed to create path (%s), err: %s", provisioningProfileDir, err)
			os.Exit(1)
		}
	}

	tempDir, err := pathutil.NormalizedOSTempDirPath("bitrise-cert-tmp")
	if err != nil {
		log.Errorf("Failed to create tmp directory, err: %s", err)
		os.Exit(1)
	}

	if exist, err := pathutil.IsPathExists(configs.KeychainPath); err != nil {
		log.Errorf("Failed to check path (%s), err: %s", configs.KeychainPath, err)
		os.Exit(1)
	} else if !exist {
		fmt.Println()
		log.Warnf("Keychain (%s) does not exist", configs.KeychainPath)

		keychainPth := fmt.Sprintf("%s-db", configs.KeychainPath)

		log.Printf(" Checking (%s)", keychainPth)

		if exist, err := pathutil.IsPathExists(keychainPth); err != nil {
			log.Errorf("Failed to check path (%s), err: %s", keychainPth, err)
			os.Exit(1)
		} else if !exist {
			log.Infof("Creating keychain: %s", configs.KeychainPath)

			if out, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "create-keychain", "-p", configs.KeychainPassword, configs.KeychainPath); err != nil {
				log.Errorf("Failed to create keychain, output: %s", out)
				log.Errorf("Failed to create keychain, err: %s", err)
				os.Exit(1)
			}
		}
	} else {
		log.Printf("Keychain already exists, using it: %s", configs.KeychainPath)
	}

	//
	// Download certificate
	fmt.Println()
	log.Infof("Downloading & installing Certificate(s)")
	fmt.Println()

	certificatePassphraseMap := map[string]string{}
	idx := 0
	for certURL, pass := range certificateURLPassphraseMap {
		log.Printf("Downloading certificate: %d/%d", idx+1, certificateCount)

		certPath := path.Join(tempDir, fmt.Sprintf("Certificate-%d.p12", idx))
		if err := downloadFile(certPath, certURL); err != nil {
			log.Errorf("Download failed, err: %s", err)
			os.Exit(1)
		}
		certificatePassphraseMap[certPath] = pass

		idx++
	}

	//
	// Install certificate
	log.Printf("Installing downloaded certificates")
	fmt.Println()

	installedCertificates := []certificateutil.CertificateInfosModel{}

	for cert, pass := range certificatePassphraseMap {
		certInfos, err := certificateutil.CertificateInfosFromP12(cert, pass)
		if err != nil {
			log.Errorf("Failed to get cert identity, error: %s", err)
			os.Exit(1)
		}
		installedCertificates = append(installedCertificates, certInfos...)

		for _, certInfo := range certInfos {
			log.Donef("%s", certInfo.CommonName)
			log.Printf("%s", certInfo.String())
			if !certInfo.EndDate.IsZero() {
				if certInfo.EndDate.Before(time.Now()) {
					log.Warnf("[!] Expired")
				}
			}
		}

		// Import items into a keychain.
		importOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "import", cert, "-k", configs.KeychainPath, "-P", pass, "-A")
		if err != nil {
			log.Errorf("Command failed, output: %s", importOut)
			log.Errorf("Command failed, err: %s", err)
			os.Exit(1)
		}
	}

	// This is new behavior in Sierra, [openradar](https://openradar.appspot.com/28524119)
	// You need to use "security set-key-partition-list -S apple-tool:,apple: -k keychainPass keychainName" after importing the item and before attempting to use it via codesign.
	osVersionCmd := command.New("sw_vers", "-productVersion")
	out, err := osVersionCmd.RunAndReturnTrimmedCombinedOutput()
	if err != nil {
		log.Errorf("Failed to get os version, error: %s", err)
		os.Exit(1)
	}

	osVersion, err := version.NewVersion(out)
	if err != nil {
		log.Errorf("Failed to parse os version (%s), error: %s", out, err)
		os.Exit(1)
	}

	sierraVersionStr := "10.12.0"
	sierraVersion, err := version.NewVersion(sierraVersionStr)
	if err != nil {
		log.Errorf("Failed to parse os version (%s), error: %s", sierraVersionStr, err)
		os.Exit(1)
	}

	if !osVersion.LessThan(sierraVersion) {
		cmd := command.New("security", "set-key-partition-list", "-S", "apple-tool:,apple:", "-k", configs.KeychainPassword, configs.KeychainPath)
		if out, err := cmd.RunAndReturnTrimmedCombinedOutput(); err != nil {
			fmt.Println()
			log.Errorf("Failed to setup keychain, err: %s", err)
			if errorutil.IsExitStatusError(err) {
				log.Printf(out)
			}
			os.Exit(1)
		}
	}
	// ---

	// Set keychain settings: Lock keychain when the system sleeps, Lock keychain after timeout interval, Timeout in seconds
	settingsOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "set-keychain-settings", "-lut", "72000", configs.KeychainPath)
	if err != nil {
		log.Errorf("Command failed, output: %s", settingsOut)
		log.Errorf("Command failed, err: %s", err)
		os.Exit(1)
	}

	// List keychains
	listKeychainsOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "list-keychains")
	if err != nil {
		log.Errorf("Command failed, output: %s", listKeychainsOut)
		log.Errorf("Command failed, err: %s", err)
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
		log.Errorf("Command failed, output: %s", listKeychainsOut)
		log.Errorf("Command failed, err: %s", err)
		os.Exit(1)
	}

	// Set the default keychain
	defaultKeychainOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "default-keychain", "-s", configs.KeychainPath)
	if err != nil {
		log.Errorf("Command failed, output: %s", defaultKeychainOut)
		log.Errorf("Command failed, err: %s", err)
		os.Exit(1)
	}

	// Unlock the specified keychain
	unlockOut, err := runCommandAndReturnCombinedStdoutAndStderr("security", "-v", "unlock-keychain", "-p", configs.KeychainPassword, configs.KeychainPath)
	if err != nil {
		log.Errorf("Command failed, output: %s", unlockOut)
		log.Errorf("Command failed, err: %s", err)
		os.Exit(1)
	}

	//
	// Install provisioning profiles
	// NOTE: the URL can be a pipe (|) separated list of Provisioning Profile URLs
	fmt.Println()
	log.Infof("Downloading & installing Provisioning Profile(s)")

	for idx, profileURL := range provisioningProfileURLs {
		fmt.Println()
		log.Printf("Downloading provisioning profile: %d/%d", idx+1, profileCount)

		provisioningProfileExt := "provisionprofile"
		if !strings.Contains(profileURL, "."+provisioningProfileExt) {
			provisioningProfileExt = "mobileprovision"
		}

		profileTmpPth := path.Join(tempDir, fmt.Sprintf("profile-%d.%s", idx, provisioningProfileExt))
		if err := downloadFile(profileTmpPth, profileURL); err != nil {
			log.Errorf("Download failed, err: %s", err)
			os.Exit(1)
		}

		fmt.Println("Installing provisioning profile")
		out, err := runCommandAndReturnCombinedStdoutAndStderr("/usr/bin/security", "cms", "-D", "-i", profileTmpPth)
		if err != nil {
			log.Errorf("Command failed, output: %s", out)
			log.Errorf("Command failed, err: %s", err)
			os.Exit(1)
		}

		outSplit := strings.Split(out, "\n")
		if len(outSplit) > 0 {
			if strings.Contains(outSplit[0], notValidParameterErrorMessage) {
				fixedOutSplit := outSplit[1:len(outSplit)]
				out = strings.Join(fixedOutSplit, "\n")
			}
		}

		tmpProvProfilePth := path.Join(tempDir, "prov")
		if err := writeBytesToFileWithPermission(tmpProvProfilePth, []byte(out), 0); err != nil {
			log.Errorf("Failed to write profile to file, error: %s", err)
			os.Exit(1)
		}

		prof, err := profileutil.ProfileFromFile(profileTmpPth)
		if err != nil {
			log.Errorf("%s", err)
			return
		}

		profileFinalPth := path.Join(provisioningProfileDir, prof.UUID+"."+provisioningProfileExt)

		log.Printf("Moving it to: %s", profileFinalPth)

		if out, err := runCommandAndReturnCombinedStdoutAndStderr("cp", profileTmpPth, profileFinalPth); err != nil {
			log.Errorf("Command failed, output: %s", out)
			log.Errorf("Command failed, err: %s", err)
			os.Exit(1)
		}

		fmt.Println()
		log.Donef(prof.Name)
		log.Printf("%s", prof.String())

		hasValidCertificate := false
		for _, devCert := range prof.DeveloperCertificates {
			for _, installedCert := range installedCertificates {
				if devCert.RawEndDate == installedCert.RawEndDate && devCert.RawSubject == installedCert.RawSubject {
					hasValidCertificate = true
					break
				}
			}
		}
		if !hasValidCertificate {
			log.Errorf("[X] No valid certificate installed for this provisioning profile")
		}
		if !prof.ExpirationDate.IsZero() {
			if prof.ExpirationDate.Before(time.Now()) {
				log.Warnf("[!] Expired")
			}
		}
	}
}
