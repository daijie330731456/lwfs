#!/usr/bin/python2
#coding=utf-8

import os
from time import time
import re

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]

groupCount = 10

def getTotalTime(fileSize):
	fileName = str(fileSize)
	file = open("timeResult", "r")
	line = file.readline()
	totalTime = 0.0
	totalCount = 0
	while line:
		pattern = re.compile(fileName + '-' + '[0-9]{1,2}:(.*)\n')
		searchObj = re.search(pattern, line)
		if searchObj:
			totalTime += float(searchObj.group(1))
			totalCount += 1

		line = file.readline()
	return totalTime / totalCount

def getEncTime(fileSize):
	fileName = str(fileSize)
	file = open("time_result_enc", "r")
	line = file.readline()
	totalTime = 0.0
	totalCount = 0
	while line:
		pattern = re.compile('/' + fileName + '-' + '[0-9]{1,2}:(.*)\n')
		searchObj = re.search(pattern, line)
		if searchObj:
			totalTime += float(searchObj.group(1))
			totalCount += 1

		line = file.readline()
	return totalTime / totalCount

def printRate():
	for fileSize in fileSizes:
		fileName = str(fileSize)
		totalTime = getTotalTime(fileSize)
		encTime = getEncTime(fileSize)
		print fileName, '----totalTime(s):', totalTime, '----encTime(us):', encTime, '---rate:', (encTime / 10000) / totalTime, '%\n'

if __name__ == '__main__':
	printRate()
