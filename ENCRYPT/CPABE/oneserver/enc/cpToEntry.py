#!/usr/bin/python2
#coding=utf-8

import os
import string
from time import time

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]

groupCount = 5


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


def enc():
	file = open('timeResult', 'w')
	for fileSize in fileSizes:
		for policySize in policySizes:
			print '----begin to mv and encrypt file :', fileSize, '-', policySize
			sourceFileName = '../testFile/' + str(fileSize)
			for i in range(groupCount):
				destFileName = '/tmp/client-entry/' + str(fileSize) + '-' + str(policySize) + '-' + str(i)
				start = time()
				os.system('cp ' + sourceFileName + ' ' + destFileName)
				os.system('setfattr -n user.policy -v \"' + policy[policySizes.index(policySize)] + '\" ' + destFileName)
				os.system('setfattr -n user.encrypt -v ABE ' + destFileName)

				end = time()

				file.write(str(fileSize) + '-' + str(policySize) + '-' + str(i) + ':')
				file.write(str(end - start))
				file.write('\n')
			
	file.close()

if __name__ == '__main__':
	enc()

