import subprocess
import os
import shutil
import sys
import axmlparserpy.axmlprinter as axmlprinter
from xml.dom import minidom
import re

input_apk = raw_input("What APK u wanna analysis? ") #Input APK name
print ("-------------------------------------------")

if os.path.isfile(input_apk):
#	print input_apk
	pass
else:
	print "Don't Exist APK file or not correct APK name"
	sys.exit()


try:
	if not os.path.isdir('./analysis'):
		subprocess.call('mkdir analysis', shell=True) #Make folder to analysis
	else:
		shutil.rmtree('./analysis') #If already exist directory, delete it
		subprocess.call('mkdir analysis', shell=True) #Make folder to analysis
except OSError as e:	
	if e.errno == 2:
		print "No such directory to remove"
		pass
	else:
		raise

subprocess.call('unzip -q *.apk -d ./analysis', shell=True) #unzip apk file

############### AndroidManifest.xml file analysis #################

ap = axmlprinter.AXMLPrinter(open('./analysis/AndroidManifest.xml','rb').read())
buff = minidom.parseString(ap.getBuff()).toxml()

#print(buff)

f=open("./analysis/new_manifest.xml",'w')
f.write(buff)
f.close()

print("This is new_manifest.xml file!!")
#subprocess.call('cat ./analysis/new_manifest.xml', shell=True)

merge_permission = []

xmlfile = open("./analysis/new_manifest.xml",'r')
lines = xmlfile.readlines()
for line in lines:
	if "android.permission" in line:
		s_permission = str(re.split("\"",line)[1])
		merge_permission.append(s_permission)
result_permission = ','.join(merge_permission)

print (result_permission)

xmlfile.close()






