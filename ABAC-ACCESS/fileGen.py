#!/usr/bin/python2
#coding=utf-8

import string
import os

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]

fileType = len(fileSizes)
policyType = len(policySizes)

policy = []
a = 'attr1 or attr2'
policy.append(a) 
    
a = '(attr1 or attr2) and (attr3 or attr4)'
policy.append(a)
a =  '((attr1 or attr2) and (attr3 or attr4)) and (attr5 or attr6)'
policy.append(a)
a =  '((attr1 or attr2)and(attr3 or attr4))and((attr5 or attr6)and(attr7 or attr8))'
policy.append(a)
a =  '(((attr1 or attr2)and(attr3 or attr4))and((attr5 or attr6)and(attr7 or attr8))) and (attr9 or attr10)'
policy.append(a)   
a =  '(((attr1 or attr2)and(attr3 or attr4))and((attr5 or attr6)and(attr7 or attr8)))and(((attr9 or attr10)and(attr11 or attr12))and((attr13 or attr14)and(attr15 or attr16)))'
policy.append(a)


def gennerateFile():
	chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345678910'

	for fileSize in fileSizes:
		for policySize in policySizes:
			print '----begin to generate file :', fileSize, 'KB,',  policySize, 'policyAttrs-----'
			
			filename = './testFile/'+ str(fileSize) + '-' + str(policySize)
			file = open(filename , 'w')
			for i in range(fileSize * 1024 / 64):
				file.write(chars)

			file.close()

			os.system('setfattr -n user.policy -v \"' + policy[policySizes.index(policySize)] + '\" ' + filename)


if __name__ == '__main__':
	gennerateFile()
	os.system("ls -l ./testFile/")

			
			







			
