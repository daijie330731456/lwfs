#!/usr/bin/python2
#coding=utf-8

import string
import os
from time import time

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]

groupCount = 50

def enc():
	file = open('timeResult', 'w')
	for fileSize in fileSizes:
		print '----begin to mv and encrypt file :', fileSize
		sourceFileName = '../testFile/' + str(fileSize)
		for i in range(groupCount):
			destFileName = '/tmp/client-entry/' + str(fileSize) + '-' + str(i)
			start = time()
			os.system('cp ' + sourceFileName + ' ' + destFileName)
			os.system('setfattr -n user.encrypt -v AES ' + destFileName)
			end = time()
			
			file.write(str(fileSize) + '-' + str(i) + ':')
			file.write(str(end - start))
			file.write('\n')
			
	file.close()

if __name__ == '__main__':
	enc()
