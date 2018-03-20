#!/usr/bin/python2
#coding=utf-8

import string
import os
from time import time

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]

groupCount = 5

def dec():
	file = open('timeResult', 'w')
	for fileSize in fileSizes:
		for policySize in policySizes:
			print '----begin to read and decrypt file :', fileSize, '-', policySize
			for i in range(groupCount):
				destFileName = '/tmp/client-entry/' + str(fileSize) + '-' + str(policySize) + '-' + str(i)
				start = time()
				file1 = open(destFileName, 'r')
				file1.read()
				file1.close()
				end = time()
			
				file.write(str(fileSize) + '-' + str(policySize) + '-' + str(i) + ':')
				file.write(str(end - start))
				file.write('\n')
			
	file.close()

if __name__ == '__main__':
	dec()
