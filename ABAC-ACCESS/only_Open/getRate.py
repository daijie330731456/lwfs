#!/usr/bin/python2
#coding=utf-8

import os
from time import time
import re

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]

groupCount = 20

def getTotalTime(fileSize, policySize):
	fileName = str(fileSize) + '-' + str(policySize)
	file = open("timeResult", "r")
	line = file.readline()
	totalTime = 0.0
	totalCount = 0
	while line:
		pattern = re.compile(fileName + ':(.*)\n')
		searchObj = re.search(pattern, line)
		if searchObj:
			totalTime += float(searchObj.group(1))
			totalCount += 1

		line = file.readline()
	return totalTime / totalCount

def getAbacTime(fileSize, policySize):
	fileName = str(fileSize) + '-' + str(policySize)
	file = open("time_result_abac", "r")
	line = file.readline()
	totalTime = 0.0
	totalCount = 0
	while line:
		pattern = re.compile('/' + fileName + ':(.*)\n')
		searchObj = re.search(pattern, line)
		if searchObj:
			totalTime += float(searchObj.group(1))
			totalCount += 1

		line = file.readline()
	return totalTime / totalCount

def printRate():
	for fileSize in fileSizes:
		for policySize in policySizes:
			fileName = str(fileSize) + '-' + str(policySize)
			totalTime = getTotalTime(fileSize, policySize)
			abacTime = getAbacTime(fileSize, policySize)
			print fileName, '----totalTime(s):', totalTime, '----abacTime(us):', abacTime, '---rate:', (abacTime / 1000000) / totalTime, '\n'

if __name__ == '__main__':
	printRate()

