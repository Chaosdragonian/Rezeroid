rule RANSOMWARE
{
	strings:
		$ransom1 = "crypto" fullword nocase ascii wide
		$ransom2 = "cipher" fullword nocase ascii wide
		$FileI = "FileInputStream" fullword nocase ascii wide
		$FileO = "FileOutputStream" fullword nocase ascii wide
		$network1 = "httpurlconnection" fullword nocase ascii wide
		$network2 = "openconnection" fullword nocase ascii wide
		$network3 = "sendtextmessage" fullword nocase ascii wide
	condition:
		(($ransom1 or $ransom2) and ($FileI or $FileO) and ($network1 or $network2 or $network3))
}

rule BODY_CAM
{
	strings:
		$body1 = "Camera" fullword nocase ascii wide
		$body2 = "getSimSerialNumber" fullword nocase ascii wide
		$body3 = "contacts" fullword nocase ascii wide
		$FileI = "FileInputStream" fullword nocase ascii wide
		$FileO = "FileOutputStream" fullword nocase ascii wide
		$network1 = "httpurlconnection" fullword nocase ascii wide
		$network2 = "openconnection" fullword nocase ascii wide
		$network3 = "sendtextmessage" fullword nocase ascii wide
	condition:
		(($body1 and $body3) or $body2) and ($FileI or $FileO) and ($network1 or $network2 or $network3)
}

rule KEYLOGGER
{
	strings:
		$keylog1 = "keylog" fullword nocase ascii wide
		$keylog2 = "keystroke" fullword nocase ascii wide
		$FileI = "FileInputStream" fullword nocase ascii wide
		$FileO = "FileOutputStream" fullword nocase ascii wide
		$network1 = "httpurlconnection" fullword nocase ascii wide
		$network2 = "openconnection" fullword nocase ascii wide
		$network3 = "sendtextmessage" fullword nocase ascii wide
	condition:
		(($keylog1 or $keylog2) and ($FileI or $FileO) and ($network1 or $network2 or $network3))
}
