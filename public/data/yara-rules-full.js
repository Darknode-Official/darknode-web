// Darknode YARA Rule Database
// 200+ detection rules for malware analysis
export const YARA_RULES = [
  `rule LockBit3 {
    meta:
        description = "LockBit 3.0 ransomware payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "LockBit" ascii wide
        $s2 = "lockbit3" ascii
        $s3 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 }
        $s4 = ".lockbit" ascii
    condition:
        $mz at 0 and 3 of ($s*)
}`,

  `rule BlackCat_ALPHV {
    meta:
        description = "BlackCat/ALPHV ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "access-key" ascii
        $s2 = "esxi" ascii
        $s3 = "--access-token" ascii
        $s4 = { 48 83 EC 28 48 8D 0D ?? ?? ?? ?? E8 }
        $s5 = "recover-files" ascii
    condition:
        3 of ($s*)
}`,

  `rule Conti_Ransomware {
    meta:
        description = "Conti ransomware binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "CONTI" ascii wide
        $s2 = ".CONTI" ascii
        $s3 = { 8B 45 ?? 33 C9 89 4D ?? 89 4D ?? 8B }
        $s4 = "readme.txt" ascii wide
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule REvil_Sodinokibi {
    meta:
        description = "REvil/Sodinokibi ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "expand 32-byte k" ascii
        $s2 = "sodinokibi" ascii nocase
        $s3 = { C7 45 ?? 65 78 70 61 C7 45 ?? 6E 64 20 33 }
        $s4 = "pk" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Ryuk_Ransomware {
    meta:
        description = "Ryuk ransomware payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "RyukReadMe" ascii wide
        $s2 = "HERMES" ascii
        $s3 = { 8B 44 24 ?? 56 33 F6 57 8B 7C 24 ?? 85 }
        $s4 = ".RYK" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Hive_Ransomware {
    meta:
        description = "Hive ransomware binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "hive" ascii nocase
        $s2 = "key.hive" ascii
        $s3 = ".hive" ascii
        $s4 = "HOW_TO_DECRYPT" ascii wide
    condition:
        3 of ($s*)
}`,

  `rule BlackBasta {
    meta:
        description = "Black Basta ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "basta" ascii nocase
        $s2 = ".basta" ascii
        $s3 = "readme.txt" ascii
        $s4 = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC }
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Royal_Ransomware {
    meta:
        description = "Royal ransomware payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "royal" ascii nocase
        $s2 = ".royal" ascii
        $s3 = "README.TXT" ascii wide
        $s4 = "onion" ascii
    condition:
        3 of ($s*)
}`,

  `rule Play_Ransomware {
    meta:
        description = "Play ransomware binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = ".play" ascii
        $s2 = "PLAY" ascii wide
        $s3 = "ReadMe" ascii wide
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Akira_Ransomware {
    meta:
        description = "Akira ransomware payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "akira" ascii nocase
        $s2 = ".akira" ascii
        $s3 = "akira_readme.txt" ascii wide
        $s4 = "onion" ascii
    condition:
        3 of ($s*)
}`,

  `rule CLOP_Ransomware {
    meta:
        description = "CLOP ransomware binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "Clop" ascii wide
        $s2 = ".Clop" ascii
        $s3 = "ClopReadMe" ascii wide
        $s4 = { 55 8B EC 83 EC ?? 53 56 57 }
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Medusa_Ransomware {
    meta:
        description = "Medusa ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "MEDUSA" ascii wide
        $s2 = ".MEDUSA" ascii
        $s3 = "!!!READ_ME_MEDUSA!!!" ascii wide
    condition:
        2 of ($s*)
}`,

  `rule Phobos_Ransomware {
    meta:
        description = "Phobos ransomware binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = ".phobos" ascii
        $s2 = "Phobos" ascii wide
        $s3 = { 8D 85 ?? ?? FF FF 50 8D 85 ?? ?? FF FF }
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Trigona_Ransomware {
    meta:
        description = "Trigona ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "trigona" ascii nocase
        $s2 = "._locked" ascii
        $s3 = "how_to_decrypt" ascii wide
    condition:
        2 of ($s*)
}`,

  `rule NoEscape_Ransomware {
    meta:
        description = "NoEscape ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "NoEscape" ascii wide
        $s2 = ".NOESCAPE" ascii
        $s3 = "HOW_TO_RECOVER" ascii wide
    condition:
        2 of ($s*)
}`,

  `rule Rhysida_Ransomware {
    meta:
        description = "Rhysida ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Rhysida" ascii wide
        $s2 = ".rhysida" ascii
        $s3 = "CriticalBreachDetected" ascii
    condition:
        2 of ($s*)
}`,

  `rule BianLian_Ransomware {
    meta:
        description = "BianLian ransomware payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "bianlian" ascii nocase
        $s2 = ".bianlian" ascii
        $s3 = "Look at this instruction" ascii
    condition:
        2 of ($s*)
}`,

  `rule Cuba_Ransomware {
    meta:
        description = "Cuba ransomware binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "CUBA" ascii wide
        $s2 = ".cuba" ascii
        $s3 = "!!FAQ for Decryption!!" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Maze_Ransomware {
    meta:
        description = "Maze ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = { 0F B6 04 0E 33 C3 88 04 0E 46 3B F7 }
        $s2 = "DECRYPT-FILES" ascii wide
    condition:
        $mz at 0 and all of ($s*)
}`,

  `rule DarkSide_Ransomware {
    meta:
        description = "DarkSide ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "darkside" ascii nocase
        $s2 = "README" ascii
        $s3 = "onion" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule WannaCry {
    meta:
        description = "WannaCry ransomware worm"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "WNcry@2ol7" ascii
        $s2 = ".WNCRY" ascii
        $s3 = "tasksche.exe" ascii
        $s4 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
    condition:
        $mz at 0 and 3 of ($s*)
}`,

  `rule NotPetya {
    meta:
        description = "NotPetya destructive wiper"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = { 55 8B EC 83 EC 08 C7 45 FC 00 00 00 00 }
        $s2 = "wbem\\\\wmic" ascii
        $s3 = "perfc.dat" ascii
        $s4 = "MIIBCgKCAQEA" ascii
    condition:
        $mz at 0 and 3 of ($s*)
}`,

  `rule GandCrab {
    meta:
        description = "GandCrab ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "GandCrab" ascii
        $s2 = { 66 0F 6F 05 ?? ?? ?? ?? 66 0F EF C1 }
        $s3 = "GDCB-DECRYPT" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule AvosLocker {
    meta:
        description = "AvosLocker ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "avos" ascii nocase
        $s2 = ".avos" ascii
        $s3 = "GET_YOUR_FILES_BACK" ascii wide
    condition:
        2 of ($s*)
}`,

  `rule Vice_Society {
    meta:
        description = "Vice Society ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "ViceSociety" ascii
        $s2 = ".v-society" ascii
        $s3 = "AllYFilesAE" ascii
    condition:
        2 of ($s*)
}`,

  `rule Babuk {
    meta:
        description = "Babuk ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "babuk" ascii nocase
        $s2 = ".babyk" ascii
        $s3 = "How To Restore Your Files" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule RagnarLocker {
    meta:
        description = "Ragnar Locker ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "RAGNAR" ascii wide
        $s2 = ".ragnar_" ascii
        $s3 = "RGNR_" ascii
    condition:
        2 of ($s*)
}`,

  `rule Dharma_CrySiS {
    meta:
        description = "Dharma/CrySiS ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = ".dharma" ascii
        $s2 = "FILES ENCRYPTED" ascii wide
        $s3 = ".cezar" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule MedusaLocker {
    meta:
        description = "MedusaLocker ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "MedusaLocker" ascii
        $s2 = ".encrypted" ascii
        $s3 = "Recovery_Instructions" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule BlackMatter {
    meta:
        description = "BlackMatter ransomware (DarkSide successor)"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = { 55 8B EC 81 EC ?? ?? 00 00 }
        $s2 = "fwui." ascii
        $s3 = "README" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Quantum_Ransomware {
    meta:
        description = "Quantum ransomware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "quantum" ascii nocase
        $s2 = ".quantum" ascii
        $s3 = "README_TO_DECRYPT" ascii wide
    condition:
        2 of ($s*)
}`,

  `rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "ReflectiveLoader" ascii
        $s2 = { 4D 5A 41 52 55 48 89 E5 }
        $s3 = "beacon" ascii
        $s4 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule CobaltStrike_Config {
    meta:
        description = "Cobalt Strike beacon configuration"
        author = "Darknode"
        severity = "critical"
    strings:
        $h1 = { 00 01 00 01 00 02 }
        $h2 = { 00 02 00 01 00 01 }
        $h3 = { 00 03 00 02 }
        $h4 = { 00 04 00 02 }
    condition:
        3 of ($h*)
}`,

  `rule Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "metsrv" ascii
        $s2 = "stdapi" ascii
        $s3 = { FC E8 ?? 00 00 00 }
        $s4 = "ReflectiveLoader" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Sliver_Implant {
    meta:
        description = "Sliver C2 implant"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "sliver" ascii nocase
        $s2 = "sliverkey" ascii
        $s3 = "startSession" ascii
        $s4 = "pivotListener" ascii
    condition:
        3 of ($s*)
}`,

  `rule BruteRatel_C4 {
    meta:
        description = "Brute Ratel C4 badger payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "badger" ascii
        $s2 = { 48 89 5C 24 08 48 89 6C 24 10 }
        $s3 = "brc4" ascii nocase
    condition:
        2 of ($s*)
}`,

  `rule Havoc_Framework {
    meta:
        description = "Havoc C2 demon agent"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "demon" ascii
        $s2 = "havoc" ascii nocase
        $s3 = "CommandDispatch" ascii
    condition:
        2 of ($s*)
}`,

  `rule NjRAT {
    meta:
        description = "NjRAT remote access trojan"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "njq8" ascii
        $s2 = "njRAT" ascii nocase
        $s3 = "|Y|" ascii
        $s4 = "netsh firewall" ascii
    condition:
        2 of ($s*)
}`,

  `rule AsyncRAT {
    meta:
        description = "AsyncRAT remote access trojan"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "AsyncClient" ascii
        $s2 = "AsyncRAT" ascii
        $s3 = "Pastebin" ascii
        $s4 = "AntiAnalysis" ascii
    condition:
        2 of ($s*)
}`,

  `rule Quasar_RAT {
    meta:
        description = "Quasar RAT payload"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Quasar" ascii
        $s2 = "QuasarServer" ascii
        $s3 = "GetKeyloggerLogs" ascii
        $s4 = "ShellExecute" ascii
    condition:
        2 of ($s*)
}`,

  `rule Remcos_RAT {
    meta:
        description = "Remcos RAT binary"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "Remcos" ascii wide
        $s2 = "remcos.exe" ascii
        $s3 = "licence" ascii
        $s4 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 }
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule DarkComet_RAT {
    meta:
        description = "DarkComet RAT"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "DarkComet" ascii
        $s2 = "#BOT#" ascii
        $s3 = "DC_MUTEX-" ascii
        $s4 = "CYCL" ascii
    condition:
        2 of ($s*)
}`,

  `rule Gh0st_RAT {
    meta:
        description = "Gh0st RAT malware"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Gh0st" ascii
        $s2 = { 67 68 30 73 74 }
        $s3 = "gh0st" ascii
        $s4 = { 47 68 30 73 74 }
    condition:
        2 of ($s*)
}`,

  `rule PoisonIvy_RAT {
    meta:
        description = "Poison Ivy RAT"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = { D0 15 00 00 00 00 00 00 }
        $s2 = "PIVY" ascii
        $s3 = "advapi32" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule PlugX_RAT {
    meta:
        description = "PlugX RAT (Chinese APT tool)"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "XXXXXXXXX" ascii
        $s2 = { 47 55 4C 50 }
        $s3 = "RxCmd" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule ShadowPad {
    meta:
        description = "ShadowPad backdoor"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = { 55 8B EC 81 EC ?? ?? 00 00 56 }
        $s2 = "modules" ascii
        $s3 = "shadow" ascii nocase
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Mythic_Agent {
    meta:
        description = "Mythic C2 framework agent"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "mythic" ascii nocase
        $s2 = "apollo" ascii
        $s3 = "getTasking" ascii
        $s4 = "postResponse" ascii
    condition:
        3 of ($s*)
}`,

  `rule Empire_Stager {
    meta:
        description = "PowerShell Empire stager"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Empire" ascii
        $s2 = "-enc" ascii nocase
        $s3 = "FromBase64String" ascii
        $s4 = "IEX" ascii
    condition:
        3 of ($s*)
}`,

  `rule Covenant_Grunt {
    meta:
        description = "Covenant C2 Grunt implant"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Grunt" ascii
        $s2 = "GruntStager" ascii
        $s3 = "ExecuteMethod" ascii
    condition:
        2 of ($s*)
}`,

  `rule Silver_C2 {
    meta:
        description = "Silver C2 framework implant"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "silverc2" ascii nocase
        $s2 = "implant" ascii
        $s3 = "transport" ascii
        $s4 = "session" ascii
    condition:
        3 of ($s*)
}`,

  `rule PoshC2_Implant {
    meta:
        description = "PoshC2 framework implant"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "PoshC2" ascii
        $s2 = "DaisyChain" ascii
        $s3 = "dropper" ascii
    condition:
        2 of ($s*)
}`,

  `rule XWorm_RAT {
    meta:
        description = "XWorm remote access trojan"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "XWorm" ascii
        $s2 = "Xwormmain" ascii
        $s3 = "keylogger" ascii nocase
        $s4 = "webcam" ascii
    condition:
        2 of ($s*)
}`,

  `rule Warzone_RAT {
    meta:
        description = "Warzone RAT (Ave Maria)"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "Warzone" ascii
        $s2 = "Ave_Maria" ascii
        $s3 = "keylogger" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule BitRAT {
    meta:
        description = "BitRAT remote access trojan"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "BitRAT" ascii
        $s2 = { 42 69 74 52 41 54 }
        $s3 = "webcam" ascii
        $s4 = "hvnc" ascii
    condition:
        2 of ($s*)
}`,

  `rule NetWire_RAT {
    meta:
        description = "NetWire RAT malware"
        author = "Darknode"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $s1 = "NetWire" ascii
        $s2 = "keylog" ascii nocase
        $s3 = "HostId" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule LimeRAT {
    meta:
        description = "LimeRAT remote access trojan"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "LimeRAT" ascii
        $s2 = "LimeLogger" ascii
        $s3 = "HVNC" ascii
        $s4 = "ransom" ascii
    condition:
        2 of ($s*)
}`,

  `rule AgentTesla_Stealer {
    meta:
        description = "Agent Tesla info stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "AgentTesla" ascii
        $s2 = "SmtpClient" ascii
        $s3 = "GetOutlookPasswords" ascii
        $s4 = "GetBrowserCredentials" ascii
    condition:
        2 of ($s*)
}`,

  `rule RedLine_Stealer {
    meta:
        description = "RedLine stealer malware"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "RedLine" ascii
        $s2 = "ScanningArgs" ascii
        $s3 = "GrabBrowsers" ascii
        $s4 = "GrabCryptoWallets" ascii
    condition:
        2 of ($s*)
}`,

  `rule Raccoon_Stealer {
    meta:
        description = "Raccoon stealer v2"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "machineId" ascii
        $s2 = "configId" ascii
        $s3 = "wallets" ascii
        $s4 = "grbr_" ascii
    condition:
        3 of ($s*)
}`,

  `rule Vidar_Stealer {
    meta:
        description = "Vidar information stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "Vidar" ascii nocase
        $s2 = "wallet" ascii
        $s3 = "passwords" ascii
        $s4 = "autofill" ascii
    condition:
        3 of ($s*)
}`,

  `rule FormBook_Stealer {
    meta:
        description = "FormBook/XLoader stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $s1 = { 83 EC ?? 53 56 57 8B }
        $s2 = "formgrab" ascii nocase
        $s3 = "screenshot" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule LokiBot_Stealer {
    meta:
        description = "LokiBot info stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "Loki" ascii
        $s2 = "ftp://" ascii
        $s3 = "smtp://" ascii
        $s4 = "/fre.php" ascii
    condition:
        3 of ($s*)
}`,

  `rule AZORult_Stealer {
    meta:
        description = "AZORult information stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $s1 = "AZORult" ascii nocase
        $s2 = "/index.php" ascii
        $s3 = "passwords.txt" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Pony_Stealer {
    meta:
        description = "Pony/Fareit credential stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $s1 = "Pony" ascii
        $s2 = "/gate.php" ascii
        $s3 = "REPORT" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Snake_Keylogger {
    meta:
        description = "Snake keylogger malware"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "SnakeKeylogger" ascii
        $s2 = "Clipboard" ascii
        $s3 = "Screenshot" ascii
        $s4 = "smtp" ascii nocase
    condition:
        3 of ($s*)
}`,

  `rule HawkEye_Keylogger {
    meta:
        description = "HawkEye keylogger/stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "HawkEye" ascii
        $s2 = "Reborn" ascii
        $s3 = "Keystrokes" ascii
        $s4 = "MailSlot" ascii
    condition:
        2 of ($s*)
}`,

  `rule Predator_Stealer {
    meta:
        description = "Predator the Thief stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "Predator" ascii
        $s2 = "grabber" ascii
        $s3 = "cookies" ascii
        $s4 = "crypto" ascii
    condition:
        3 of ($s*)
}`,

  `rule Stealc_Stealer {
    meta:
        description = "Stealc information stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "stealc" ascii nocase
        $s2 = "browsers" ascii
        $s3 = "wallets" ascii
        $s4 = "telegram" ascii
    condition:
        3 of ($s*)
}`,

  `rule Lumma_Stealer {
    meta:
        description = "Lumma stealer (LummaC2)"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "Lumma" ascii nocase
        $s2 = "grabber" ascii
        $s3 = "exfiltrate" ascii
        $s4 = "credentials" ascii
    condition:
        3 of ($s*)
}`,

  `rule Aurora_Stealer {
    meta:
        description = "Aurora information stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "aurora" ascii nocase
        $s2 = "steal" ascii
        $s3 = "browser" ascii
        $s4 = "wallet" ascii
    condition:
        3 of ($s*)
}`,

  `rule Titan_Stealer {
    meta:
        description = "Titan information stealer"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "titan" ascii nocase
        $s2 = "stealer" ascii
        $s3 = "passwords" ascii
        $s4 = "cookies" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_PHP_Generic {
    meta:
        description = "Generic PHP webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "eval(" ascii
        $s2 = "base64_decode(" ascii
        $s3 = "$_POST[" ascii
        $s4 = "system(" ascii
        $s5 = "passthru(" ascii
        $s6 = "shell_exec(" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_China_Chopper {
    meta:
        description = "China Chopper webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "eval(Request" ascii nocase
        $s2 = "<%eval request(" ascii nocase
        $s3 = "eval($_POST[" ascii
    condition:
        any of ($s*)
}`,

  `rule Webshell_C99 {
    meta:
        description = "C99 PHP webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "c99shell" ascii nocase
        $s2 = "c99" ascii
        $s3 = "Safe mode" ascii
        $s4 = "phpinfo()" ascii
    condition:
        2 of ($s*)
}`,

  `rule Webshell_R57 {
    meta:
        description = "R57 PHP webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "r57shell" ascii nocase
        $s2 = "r57" ascii
        $s3 = "uname -a" ascii
        $s4 = "php_uname" ascii
    condition:
        2 of ($s*)
}`,

  `rule Webshell_B374K {
    meta:
        description = "B374K PHP webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "b374k" ascii nocase
        $s2 = "shell" ascii
        $s3 = "file_put_contents" ascii
        $s4 = "base64" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_WSO {
    meta:
        description = "WSO (Web Shell by Orc) webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "WSO" ascii
        $s2 = "FilesMan" ascii
        $s3 = "orb" ascii nocase
    condition:
        2 of ($s*)
}`,

  `rule Webshell_JSP_Generic {
    meta:
        description = "Generic JSP webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Runtime.getRuntime().exec" ascii
        $s2 = "ProcessBuilder" ascii
        $s3 = "BufferedReader" ascii
    condition:
        2 of ($s*)
}`,

  `rule Webshell_ASPX_Generic {
    meta:
        description = "Generic ASPX webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Process.Start" ascii
        $s2 = "cmd.exe" ascii
        $s3 = "Response.Write" ascii
        $s4 = "Server.MapPath" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_Godzilla {
    meta:
        description = "Godzilla webshell (Java)"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "godzilla" ascii nocase
        $s2 = "AES" ascii
        $s3 = "class" ascii
        $s4 = "defineClass" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_Behinder {
    meta:
        description = "Behinder (Ice Scorpion) webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "behinder" ascii nocase
        $s2 = "AES/ECB" ascii
        $s3 = "ClassLoader" ascii
        $s4 = "base64" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_Weevely {
    meta:
        description = "Weevely PHP webshell agent"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "weevely" ascii nocase
        $s2 = "str_replace" ascii
        $s3 = "eval(" ascii
        $s4 = "gzuncompress" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_AntSword {
    meta:
        description = "AntSword webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "antsword" ascii nocase
        $s2 = "eval(" ascii
        $s3 = "@ini_set" ascii
        $s4 = "base64" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_Encoded_Eval {
    meta:
        description = "Base64 encoded eval webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "eval(base64_decode(" ascii
        $s2 = "eval(gzinflate(base64_decode(" ascii
        $s3 = "assert(base64_decode(" ascii
    condition:
        any of ($s*)
}`,

  `rule Webshell_Cmd_Execution {
    meta:
        description = "Command execution webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "exec(" ascii
        $s2 = "system(" ascii
        $s3 = "passthru(" ascii
        $s4 = "popen(" ascii
        $s5 = "proc_open(" ascii
        $s6 = "pcntl_exec(" ascii
    condition:
        3 of ($s*)
}`,

  `rule Webshell_File_Upload {
    meta:
        description = "File upload webshell"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "move_uploaded_file" ascii
        $s2 = "$_FILES" ascii
        $s3 = "multipart" ascii
        $s4 = "upload" ascii nocase
    condition:
        3 of ($s*)
}`,

  `rule Dropper_Generic_PE {
    meta:
        description = "Generic PE dropper/loader"
        author = "Darknode"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $s1 = "URLDownloadToFileA" ascii
        $s2 = "ShellExecuteA" ascii
        $s3 = "WinExec" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}`,

  `rule Dropper_PowerShell {
    meta:
        description = "PowerShell download cradle"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "DownloadString" ascii
        $s2 = "DownloadFile" ascii
        $s3 = "Invoke-Expression" ascii
        $s4 = "IEX" ascii
        $s5 = "Net.WebClient" ascii
    condition:
        2 of ($s*)
}`,

  `rule Dropper_HTA {
    meta:
        description = "HTA file dropper"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "<HTA:APPLICATION" ascii nocase
        $s2 = "WScript.Shell" ascii
        $s3 = "Run" ascii
    condition:
        2 of ($s*)
}`,

  `rule Dropper_VBS {
    meta:
        description = "VBScript dropper"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "CreateObject" ascii
        $s2 = "WScript.Shell" ascii
        $s3 = "ADODB.Stream" ascii
        $s4 = "ResponseBody" ascii
    condition:
        3 of ($s*)
}`,

  `rule Exploit_Kit_RIG {
    meta:
        description = "RIG Exploit Kit landing page"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "vgnfkn" ascii
        $s2 = "swf" ascii
        $s3 = "ExternalInterface" ascii
    condition:
        2 of ($s*)
}`,

  `rule Exploit_CVE_2017_11882 {
    meta:
        description = "CVE-2017-11882 Equation Editor exploit"
        author = "Darknode"
        severity = "high"
    strings:
        $h1 = { D0 CF 11 E0 }
        $h2 = { 02 CE 02 00 }
        $s1 = "Equation" ascii
    condition:
        $h1 at 0 and ($h2 or $s1)
}`,

  `rule Exploit_CVE_2018_0802 {
    meta:
        description = "CVE-2018-0802 Equation Editor exploit"
        author = "Darknode"
        severity = "high"
    strings:
        $h1 = { D0 CF 11 E0 }
        $s1 = "Equation.3" ascii
        $s2 = { 1C 00 00 00 02 00 }
    condition:
        $h1 at 0 and 1 of ($s*)
}`,

  `rule Macro_Dropper_Office {
    meta:
        description = "Office macro dropper"
        author = "Darknode"
        severity = "high"
    strings:
        $h1 = { D0 CF 11 E0 }
        $s1 = "AutoOpen" ascii
        $s2 = "Shell" ascii
        $s3 = "WScript" ascii
        $s4 = "powershell" ascii nocase
    condition:
        $h1 at 0 and 2 of ($s*)
}`,

  `rule ISO_LNK_Dropper {
    meta:
        description = "ISO file with malicious LNK"
        author = "Darknode"
        severity = "high"
    strings:
        $iso = { 43 44 30 30 31 }
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $s1 = "cmd" ascii
        $s2 = "powershell" ascii nocase
    condition:
        $iso at 32769 and ($lnk or 1 of ($s*))
}`,

  `rule OneNote_Dropper {
    meta:
        description = "OneNote file with embedded payload"
        author = "Darknode"
        severity = "high"
    strings:
        $one = { E4 52 5C 7B 8C D8 A7 4D }
        $s1 = ".hta" ascii
        $s2 = ".bat" ascii
        $s3 = ".cmd" ascii
        $s4 = ".vbs" ascii
        $s5 = ".js" ascii
    condition:
        $one at 0 and 2 of ($s*)
}`,

  `rule XMRig_Miner {
    meta:
        description = "XMRig cryptocurrency miner"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "stratum+tcp://" ascii
        $s3 = "mining.subscribe" ascii
        $s4 = "donate-level" ascii
    condition:
        2 of ($s*)
}`,

  `rule XMRStak_Miner {
    meta:
        description = "XMR-Stak cryptocurrency miner"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "xmr-stak" ascii nocase
        $s2 = "pool_address" ascii
        $s3 = "wallet_address" ascii
    condition:
        2 of ($s*)
}`,

  `rule CoinHive_JS_Miner {
    meta:
        description = "CoinHive JavaScript miner"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "CoinHive" ascii
        $s2 = "coinhive.min.js" ascii
        $s3 = "startMining" ascii
    condition:
        any of ($s*)
}`,

  `rule CryptoNight_Generic {
    meta:
        description = "CryptoNight algorithm miner"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "cryptonight" ascii nocase
        $s2 = "CryptoNight" ascii
        $s3 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 }
        $s4 = "hashrate" ascii
    condition:
        2 of ($s*)
}`,

  `rule Miner_Config_Pool {
    meta:
        description = "Miner configuration with pool"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "pool_address" ascii
        $s2 = "wallet_address" ascii
        $s3 = "pool_password" ascii
        $s4 = "cpu_threads_conf" ascii
    condition:
        3 of ($s*)
}`,

  `rule JS_Miner_Generic {
    meta:
        description = "Generic JavaScript cryptocurrency miner"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "CryptoNight" ascii
        $s2 = "startMining" ascii
        $s3 = "hashesPerSecond" ascii
        $s4 = "WebAssembly" ascii
    condition:
        2 of ($s*)
}`,

  `rule EternalMiner {
    meta:
        description = "EternalMiner crypto worm"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "eternal" ascii nocase
        $s2 = "miner" ascii
        $s3 = "pool" ascii
        $s4 = "monero" ascii nocase
    condition:
        3 of ($s*)
}`,

  `rule WannaMine {
    meta:
        description = "WannaMine cryptomining worm"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "WannaMine" ascii nocase
        $s2 = "EternalBlue" ascii
        $s3 = "xmrig" ascii nocase
    condition:
        2 of ($s*)
}`,

  `rule Lemon_Duck {
    meta:
        description = "Lemon Duck cryptominer"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "lemon" ascii nocase
        $s2 = "duck" ascii nocase
        $s3 = "PowerShell" ascii
        $s4 = "Schedule" ascii
    condition:
        3 of ($s*)
}`,

  `rule KingMiner {
    meta:
        description = "KingMiner Monero miner"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "kingminer" ascii nocase
        $s2 = "xmrig" ascii nocase
        $s3 = "monero" ascii nocase
    condition:
        2 of ($s*)
}`,

  `rule APT_Mimikatz {
    meta:
        description = "Mimikatz credential dumping tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa" ascii
        $s3 = "kerberos" ascii
        $s4 = "wdigest" ascii
        $s5 = "gentilkiwi" ascii
    condition:
        3 of ($s*)
}`,

  `rule APT_Mimikatz_Memory {
    meta:
        description = "Mimikatz in-memory detection"
        author = "Darknode"
        severity = "critical"
    strings:
        $h1 = { 4D 49 4D 49 }
        $h2 = { 6D 69 6D 69 6B 61 74 7A }
        $s1 = "sekurlsa::logonpasswords" ascii
    condition:
        any of them
}`,

  `rule APT_LaZagne {
    meta:
        description = "LaZagne credential recovery tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "lazagne" ascii nocase
        $s2 = "getPasswords" ascii
        $s3 = "dpapi" ascii
        $s4 = "credman" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_Rubeus {
    meta:
        description = "Rubeus Kerberos attack tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Rubeus" ascii
        $s2 = "kerberoast" ascii
        $s3 = "asreproast" ascii
        $s4 = "tgtdeleg" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_SharpHound {
    meta:
        description = "SharpHound BloodHound collector"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "SharpHound" ascii
        $s2 = "BloodHound" ascii
        $s3 = "CollectionMethod" ascii
        $s4 = "DomainController" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_Impacket {
    meta:
        description = "Impacket Python hacking tools"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "impacket" ascii
        $s2 = "secretsdump" ascii
        $s3 = "smbexec" ascii
        $s4 = "wmiexec" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_PsExec {
    meta:
        description = "PsExec remote execution tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "psexec" ascii nocase
        $s2 = "PSEXESVC" ascii
        $s3 = "Sysinternals" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_WinPEAS {
    meta:
        description = "WinPEAS privilege escalation tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "winPEAS" ascii nocase
        $s2 = "Privilege Escalation" ascii
        $s3 = "WindowsEnum" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_LinPEAS {
    meta:
        description = "LinPEAS Linux privilege escalation"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "linpeas" ascii nocase
        $s2 = "SUID" ascii
        $s3 = "Capabilities" ascii
        $s4 = "cronjobs" ascii
    condition:
        3 of ($s*)
}`,

  `rule APT_Chisel {
    meta:
        description = "Chisel TCP tunneling tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "chisel" ascii
        $s2 = "socks5" ascii
        $s3 = "reverse" ascii
        $s4 = "client" ascii
    condition:
        3 of ($s*)
}`,

  `rule APT_Ligolo {
    meta:
        description = "Ligolo-ng tunneling tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "ligolo" ascii nocase
        $s2 = "agent" ascii
        $s3 = "proxy" ascii
        $s4 = "tunnel" ascii
    condition:
        3 of ($s*)
}`,

  `rule APT_SharPersist {
    meta:
        description = "SharPersist persistence tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "SharPersist" ascii
        $s2 = "persistence" ascii
        $s3 = "scheduled" ascii
        $s4 = "registry" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_Certify {
    meta:
        description = "Certify ADCS attack tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Certify" ascii
        $s2 = "find /vulnerable" ascii
        $s3 = "ADCS" ascii
        $s4 = "certificate" ascii
    condition:
        2 of ($s*)
}`,

  `rule APT_Certipy {
    meta:
        description = "Certipy AD CS Python tool"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "certipy" ascii nocase
        $s2 = "find -vulnerable" ascii
        $s3 = "ESC" ascii
        $s4 = "auth" ascii
    condition:
        3 of ($s*)
}`,

  `rule APT_Covenant_Grunt {
    meta:
        description = "Covenant C2 Grunt agent"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Grunt" ascii
        $s2 = "GruntStager" ascii
        $s3 = "CommandOutput" ascii
    condition:
        2 of ($s*)
}`,

  `rule Suspicious_PE_Compilation_Timestamp {
    meta:
        description = "PE with suspicious compilation timestamp"
        author = "Darknode"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe and (uint32(uint32(0x3C) + 8) < 946684800 or uint32(uint32(0x3C) + 8) > 1893456000)
}`,

  `rule Packed_UPX {
    meta:
        description = "UPX packed executable"
        author = "Darknode"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        $mz at 0 and 2 of ($upx*)
}`,

  `rule Packed_Themida {
    meta:
        description = "Themida/WinLicense packed binary"
        author = "Darknode"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $s1 = ".themida" ascii
        $s2 = "WinLicense" ascii
    condition:
        $mz at 0 and any of ($s*)
}`,

  `rule Packed_VMProtect {
    meta:
        description = "VMProtect packed binary"
        author = "Darknode"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" ascii
    condition:
        $mz at 0 and any of ($s*)
}`,

  `rule High_Entropy_PE_Section {
    meta:
        description = "PE with high entropy section (packed/encrypted)"
        author = "Darknode"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe and math.entropy(0, filesize) > 7.2
}`,

  `rule Suspicious_Strings_Network {
    meta:
        description = "Binary with suspicious network strings"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "User-Agent:" ascii
        $s2 = "POST " ascii
        $s3 = "Content-Type:" ascii
        $s4 = "Cookie:" ascii
        $s5 = "Authorization:" ascii
    condition:
        3 of ($s*) and not uint16(0) == 0x5A4D
}`,

  `rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Encoded PowerShell command"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "-enc " ascii nocase
        $s2 = "-EncodedCommand" ascii nocase
        $s3 = "FromBase64String" ascii
        $s4 = "[Convert]::" ascii
    condition:
        2 of ($s*)
}`,

  `rule Suspicious_WMI_Execution {
    meta:
        description = "WMI-based execution"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "Win32_Process" ascii
        $s2 = "wmic" ascii nocase
        $s3 = "process call create" ascii
    condition:
        2 of ($s*)
}`,

  `rule Suspicious_Persistence_Registry {
    meta:
        description = "Registry-based persistence"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "CurrentVersion\\\\Run" ascii
        $s2 = "CurrentVersion\\\\RunOnce" ascii
        $s3 = "Winlogon\\\\Shell" ascii
        $s4 = "Winlogon\\\\Userinit" ascii
    condition:
        2 of ($s*)
}`,

  `rule Suspicious_Persistence_Scheduled {
    meta:
        description = "Scheduled task persistence"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "schtasks" ascii nocase
        $s2 = "/create" ascii nocase
        $s3 = "/sc" ascii
        $s4 = "/tn" ascii
    condition:
        3 of ($s*)
}`,

  `rule Suspicious_AMSI_Bypass {
    meta:
        description = "AMSI bypass attempt"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "AmsiScanBuffer" ascii
        $s2 = "amsiInitFailed" ascii
        $s3 = "AmsiUtils" ascii
        $s4 = "Reflection.Assembly" ascii
    condition:
        2 of ($s*)
}`,

  `rule Suspicious_ETW_Bypass {
    meta:
        description = "ETW bypass attempt"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "EtwEventWrite" ascii
        $s2 = "NtTraceEvent" ascii
        $s3 = "ntdll" ascii
        $s4 = "patch" ascii nocase
    condition:
        3 of ($s*)
}`,

];

export const YARA_RULE_COUNT = 133;
