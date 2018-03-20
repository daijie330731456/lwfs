#!/usr/bin/python2
#coding=utf-8

import os
from time import time

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]

groupCount = 50


def catFile():
	file = open('timeResult', 'w')
	for fileSize in fileSizes:
		for policySize in policySizes:
			print '----begin to write file :', fileSize, '-', policySize,'-----'
				
			fileName = str(fileSize) + '-' + str(policySize)
			fileLocal = open("../testFile/" + fileName, 'r')
			readStr = fileLocal.read()
		
			for i in range(groupCount):
								
				start = time()
				#os.system('cat /tmp/client-entry/'+ str(fileSize) + '-' + str(policySize))
				file1 = open("/tmp/client-entry/" + fileName, 'w')
				file1.write(readStr)				
				end = time()
				file1.close()
				file.write(fileName + ':')
				file.write(str(end - start))
				file.write('\n')
			fileLocal.close()
	file.close()

#不能sudo执行,直接变成root权限了

if __name__ == '__main__':
	catFile()

