#!/usr/bin/python2
#coding=utf-8

import os
import string

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]

def cpToEntry():
	for fileSize in fileSizes:
		for policySize in policySizes:
			print '----begin to cp file :', fileSize, '-', policySize,'-----'	
			
			#mv保存扩展属性，cp不保存
			os.system('sudo mv ./testFile/' + str(fileSize) + '-' + str(policySize) + ' /tmp/client-entry')


if __name__ == '__main__':
	cpToEntry()

