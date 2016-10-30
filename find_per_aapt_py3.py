###################### python 3.x + aapt ############################

import subprocess

print ("\n[*] Start to analysis AndroidManifest.xml file")
print ("[*] Find android permission!")
print ("===============================================")

subprocess.call('aapt dump badging *.apk | grep android.permission',shell=True)




