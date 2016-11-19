import os, yara

print ("############## Start YARA Rule!!! ###############")

target = ""
Analysis_path = "/home/pro/bin"

rules = yara.compile(filepath='./result_rule.yar') #Input rule path

for root, dirs, files in os.walk(Analysis_path): #Input analysis path
	for file in files:
		if file.find('.java') >= 0:
			print (file)
			target = Analysis_path + file			
			matches = rules.match(target)


			if len(matches.values()) == 0:
				print ("Malware type : ETC")
				pass
			else:
				key = (matches['main'])
				print ("Malware type : %s" %key[0]['rule'])

