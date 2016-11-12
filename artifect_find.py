import sys
import zipfile
import shutil
import subprocess
import os
import re
import traceback
import json
import hashlib
import pymysql

from lib.dexparser import Dexparser

dexList = [] #dexfile list

#program usage
def usage():
	print ("androtools : no file specified")
	print ("./androtools <APK_FILE>")


#program information
def about(apkfile):
	print ("Target APK Path : %s" %apkfile)


#check target file that this is vaild apk file
def is_android(zfile):
	for fname in zfile.namelist():
		if "AndroidManifest.xml" in fname:
			return True
		elif "resources.arsc" in fname:
			return True
		else:
			pass
	return False


#filehash extractor
def filehash(apkfile, mode):
	if mode == "md5":
		with open(apkfile, 'rb') as f:
			m = hashlib.md5()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()
	elif mode == "sha1":
		with open(apkfile, 'rb') as f:
			m = hashlib.sha1()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()
	elif mode == "sha256":
		with open(apkfile, 'rb') as f:
			m = hashlib.sha256()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()

	else:
		return ""


#extract dex file to temp file
def extractDEX(zfile):
	global dexList
	for fname in zfile.namelist():
		if fname[-4:] == ".dex": #if file extension is dex
			zfile.extract(fname, "temp")
			dexpath = os.path.join("temp", fname)
			dexhash = filehash(dexpath, "md5")
			print ("dexpath : %s" %dexpath)
			print ("dexhash : %s" %dexhash)
			shutil.move(dexpath, os.path.join("temp", dexhash + ".dex"))
			dexList.append(dexhash + ".dex")


def getManifest(cur,apkfile):
	
	cmd = ""
	mysql_list = ""

	print ("[*] Extracting Permission in AndroidManifest.xml File...")
	print ("############## Permission List in AndroidManifest.xml ##############")
	infocmd = "aapt dump badging %s | grep uses-permission > per_m.txt" %apkfile
	subprocess.call(infocmd,shell=True)
	f = open("./per_m.txt",'r')
	while True:
		line = f.readline()
		if not line: break
		line = line.split('\'')[-2]
		line = line.split('.')[-1]
		mysql_list += line + ','
	f.close()
	print (mysql_list)
	subprocess.call("rm -r per_m.txt",shell=True)
	cmd = ("INSERT INTO APK_XML(PERMISSION) VALUES(%s)""")
	cur.execute(cmd,mysql_list)

#find suspicious string in dex and replace if highlight
def findSuspicious(cur,stringlist):
	dexstrlist = []
	emaillist = ""
	urllist = ""
	iplist = ""
	phonelist = ""
#	print (stringlist)
	for i in range(len(stringlist)):
		email 	= re.findall(b'([\w.-]+)@([\w.-]+)', stringlist[i])
		url 	= re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', stringlist[i])
		ip 	= re.findall(b'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', stringlist[i])
		phone = re.findall(b'\d{2,3}-\d{3,4}-\d{3,4}',stringlist[i])
#		user_id	= re.findall(b'%(id)%',stringlist[i])

		if email:
			dexstrlist.append(str(email[0][0] + "@" + email[0][1]))
			emaillist += str(email[0][0] + "@" + email[0][1]).replace("b'", '')
		if url:
			dexstrlist.append(str(url[0]))
			if ((str(url[0]).replace("b'", '')).find("schemas.android.com")) >= 0:
				pass
			else:
				urllist += str(url[0]).replace("b'", '')
		if ip:
			dexstrlist.append(str(ip[0]))
			iplist += str(ip[0]).replace("b'", '')
		if phone:
			dexstrlist.append(str(phone[0]))
			phonelist += str(phone[0]).replace("b'", '')	


	print ("######################## _Classes.dex_ File Artifects list ##########################")
#	print (dexstrlist)
	print ("print email list : %s" %emaillist)
	print ("print url list : %s" %urllist)
	print ("print ip list : %s" %iplist)
	print ("print phone list : %s" %phonelist)

	cmd = """INSERT INTO ARTIFACT_INFO(A_DOMAIN,A_MAIL,A_IP,A_PHONE) VALUES (%s, %s, %s, %s)"""
	cur.execute(cmd,(urllist,emaillist,iplist,phonelist))



def parseDEX(cur):
#def parseDEX(cur):
	global dexList

	for dexfile in dexList:
		parse = Dexparser(os.path.join("temp", dexfile))
		string = parse.string_list()
#		typeid = parse.typeid_list()
#		method = parse.method_list()
#		findSuspicious(string)
		findSuspicious(cur,string)
#		print (string)

def nativeparser(solist):
	filterList = []
	for sofile in solist:
		with open(os.path.join("temp", sofile[1] + ".so"), 'rb') as f:
			data = f.read()
			email 	= re.findall(r'([\w.-]+)@([\w.-]+)', data)
			url 	= re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)
			ip 	= re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', data)

			if email:
				if str(email[0][0] + "@" + email[0][1]) not in filterList:
					filterList.append(str(email[0][0] + "@" + email[0][1]))
			if url:
				if str(url[0]) not in filterList:
					filterList.append(str(url[0]))
			if ip:
				if str(ip[0]) not in filterList:
					filterList.append(str(ip[0]))
	print ("######################## _.so_ File Artifects List ##########################")
	print (filterList)


#native file information
def nativefile(zfile):
	print ("[*] Extracting Native File Data...")
	solist = []
	for fname in zfile.namelist():
		if fname[-3:] == ".so":
			tempArr = []
			sofile = os.path.basename(fname)
			source = zfile.open(fname)
			target = file(os.path.join("temp", sofile), "wb")
			with source, target:
				shutil.copyfileobj(source, target)
			sohash = filehash(os.path.join("temp", sofile), "sha1")
			shutil.move(os.path.join("temp", sofile), os.path.join("temp", sohash + ".so"))
			tempArr.append(fname)
			tempArr.append(sohash)
			solist.append(tempArr)

	nativeparser(solist)

#Parsing Icon file
def parse_icon(apkfile):

	print ("############### Parsing IconFile ###############")

	iconfile_name = ""
	if not os.path.isdir('./pp_icon'):
		subprocess.call("mkdir pp_icon",shell=True)
	else:
		subprocess.call("rm -r pp_icon",shell=True)
		subprocess.call("mkdir pp_icon",shell=True)
	cmd_line = "unzip -q %s -d pp_icon" %apkfile
	subprocess.call(cmd_line,shell=True)

	for (path,dir,files) in os.walk("./pp_icon/res/"):
		for filename in files:
			ext = os.path.splitext(filename)[-1]
			if path.find('drawable') >= 0:
				pass
			elif path.find('layout') >= 0:
				pass
			else:
				if filename == iconfile_name:
					pass
				else:
					if (ext == ".png" or ext == ".jpg"):
						if (filename.find("ic") >= 0):
							print (path + "/" + filename)
							subprocess.call("cp %s ./iconfile.png" %(path + "/" + filename),shell=True)
							iconfile_name = filename


	subprocess.call("rm -rf pp_icon",shell=True)


#delete temp file directory
def delTemp():
	subprocess.call("rm -rf temp",shell=True)


#logging error to error_log.txt
def logError(error_msg):
	f = open('error_log.txt', 'a+')
	f.write('[*] ' + error_msg + '\n')
	f.close()


def main(apkfile):
	try:
		about(apkfile) #program information
		isVaild = zipfile.is_zipfile(apkfile) #check vaild zip container
		if isVaild:
			zfile = zipfile.ZipFile(apkfile)
			isAndroid = is_android(zfile) #check vaild android apk file
			if isAndroid:
				print ("[*] Analysis start!")

				con = pymysql.connect(host='165.132.221.252',user='root',passwd='keroro2424',db='rezeroid')
				cur = con.cursor()
				
				extractDEX(zfile) #extract dex file

#				getManifest(apkfile)
				getManifest(cur,apkfile)

#				parseDEX()
				parseDEX(cur)

				nativefile(zfile)

				parse_icon(apkfile)

				con.commit()

				con.close()
				#extractString(report, apkfile)


			else:
				print ("[*] Sorry, We can\'t analyze this file")
		else:
			print ("[*] Sorry, We can\'t analyze this file")
		delTemp()
		print ("[*] Analysis complete!")
	except Exception as e:
		logError(str(traceback.format_exc()))
		print ("[*] Androtools Exception - Error logged!")

if __name__ == '__main__':
	try:
		main(sys.argv[1])
	except:
		usage()
