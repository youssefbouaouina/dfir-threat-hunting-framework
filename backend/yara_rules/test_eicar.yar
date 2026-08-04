rule EICAR_Test_String {
  meta:
    description = "Detects the EICAR antivirus test string"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $eicar
}
