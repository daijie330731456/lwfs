#!/usr/bin/python2
#coding=utf-8

import string
import os

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]

def gennerateFile():
	chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345678910'

	for fileSize in fileSizes:
			print '----begin to generate file :', fileSize, 'KB,'
			
			filename = './testFile/'+ str(fileSize)
			file = open(filename , 'w')
			for i in range(fileSize * 1024 / 64):
				file.write(chars)

			file.close()


if __name__ == '__main__':
	gennerateFile()
	os.system("ls -l ./testFile/")

			
			







			
