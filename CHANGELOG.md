## Changelog (Current version: 1.5.1)

-----------------

### 1.5.1 (2016 Jun 07)

* [c9c9925] prepare for 1.5.1
* [b7abc0b] Merge pull request #15 from bitrise-io/required_fix
* [82264aa] Trim fix
* [6aa0b6d] secure inputs
* [337fdbc] do not require certificate_url & provisioning_profile_url

### 1.5.0 (2016 Jun 01)

* [39c4f21] relelase configs
* [28b168a] Merge pull request #14 from bitrise-io/keychain_list_fix
* [8fc6c09] keychain list fix
* [b0709c1] STEP_GIT_VERION_TAG_TO_SHARE: 1.4.2

### 1.4.2 (2016 Apr 22)

* [2f5b45a] testing BITRISE_PROVISIONING_PROFILE_PATH output in bitrise run test
* [2bf9e04] logging fix/revision - related to "profileCount"
* [de2a0df] Merge pull request #13 from rymir/export-prov-prof-path
* [0d0b8a6] Export BITRISE_PROVISIONING_PROFILE_PATH too

### 1.4.1 (2016 Apr 21)

* [78f3f0d] STEP_GIT_VERION_TAG_TO_SHARE: 1.4.1
* [fd595eb] Merge pull request #12 from olegoid/master
* [3289f63] Add 3rd party mac certificates recognition

### 1.4.0 (2015 Dec 11)

* [5da704a] security list-keychains : verbose removed
* [df8b903] an example fix
* [d63b807] URL inputs: note about file:// scheme
* [598137c] removed unnecessary check
* [c1fbb89] quotation
* [02ed136] MY_STEPLIB_REPO_FORK_GIT_URL: $MY_STEPLIB_REPO_FORK_GIT_URL
* [8b9adab] STEP_GIT_VERION_TAG_TO_SHARE: 1.4.0
* [f9d9a9d] Merge pull request #8 from godrei/golang
* [4e70008] download retry fixes
* [691b017] PR fix
* [3b2a409] PrintFatallnf moved to main
* [a4c6326] security
* [6efeba1] PR fixes
* [ce45ad4] retry download, copy instead of move files
* [963f6d1] removed references
* [33567dd] removed log
* [f4e3bfe] fixed search for imported cert & golang
* [398c89c] share 1.3.0

### 1.3.0 (2015 Nov 23)

* [49a3fc2] grep revision (added -e)
* [812cfed] grep fix
* [9eb8942] logging
* [30aefa5] logging
* [f486d8a] certificate info - Mac specific code added & full available list
* [1561adc] err handling in ProvProfile download
* [8acdc45] tmp dir path revision, extension priority revision
* [70c07f7] Merge pull request #7 from vasarhelyia/master
* [1bcc684] Using provisionprofile extension as fallback for mac support

### 1.2.2 (2015 Nov 06)

* [f61d71f] bitrise.yml revision & added share-this-step workflow
* [ba6c97c] further log revision 2
* [36c0ab1] further log revision
* [7c94bb7] bit of logging revision & do not print the passphrase of the certificate
* [0444ad3] Merge pull request #5 from bazscsa/patch-1
* [9704721] Update step.yml

### 1.2.1 (2015 Sep 24)

* [57f127a] minor logging fixes
* [8982d36] executable file flag removed from bitrise.yml LICENSE and README

### 1.2.0 (2015 Sep 14)

* [38cc056] exporting BITRISE_PROVISIONING_PROFILE_ID and BITRISE_CODE_SIGN_IDENTITY
* [2e578f6] Merge pull request #3 from gkiki90/input_fix
* [b5ec7ef] yml fix

### 1.1.1 (2015 Sep 12)

* [dc2daac] Merge pull request #2 from gkiki90/input_fix
* [99e0a8f] input fix

### 1.1.0 (2015 Sep 08)

* [70d1670] bitrise stack related update - README update
* [643de77] bitrise stack related update - removed old step.yml
* [098b5cc] bitrise stack related update
* [306b00f] Merge pull request #1 from gkiki90/update
* [9b6b2ee] update
* [57bad79] debug log
* [ab222dd] fix: don't fail if keychain already exists, instead we should get the keychain password as an input
* [23d8980] step.yml switch : old is now .yml.old and the new one is just step.yml, as required for the new bitwise-cli tool

-----------------

Updated: 2016 Jun 07