#!/usr/bin/python2
#coding=utf-8

import os
from time import time
import re

############################################################
#time_result_dec中是"fd:时间"的格式
#系统是按照128k为单位读,所以一个文件可能读了很多次
#没法记录loc,只能记录fd
############################################################

fileSizes = [128, 256, 512, 1024, 2048, 4096, 8192, 16384]
policySizes = [2, 4, 6, 8, 10, 16]
lineFlag = [0, 1, 3, 7, 15, 31, 63, 127, 255]


groupCount = 5

#计算行数是否正确
def isCorrect():
	file = open("time_result_dec", "r")
	lineCount = len(file.readlines())
	print "getline:", lineCount

	count = 0	
	for fileSize in fileSizes:
		count += (fileSize / 128)
	print "should get:", count * groupCount * len(policySizes)

	if count*groupCount* len(policySizes) == lineCount:
		return 1
	else:
		return 0


def getTotalTime(fileSize, policySize):
	fileName = str(fileSize) + '-' + str(policySize)
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

def timeCombine():
	resourceFile = open ("time_result_dec", "r")
	combineFile = open("combineTime", "w")


	pattern = re.compile('(.*):(.*)\n')
	for fileSize in fileSizes:
		for policySize in policySizes:
			for i in range(groupCount):
				filename = str(fileSize) + '-' + str(policySize) + '-' + str(i)
				totalTime = 0
				for i in range(fileSize / 128):
					line = resourceFile.readline()
					searchObj = re.search(pattern, line)
					if searchObj:
						totalTime += float(searchObj.group(2))
				combineFile.write(filename + ':' + str(totalTime) + '\n' )

	resourceFile.close()
	combineFile.close()
					
def getDecTime(fileSize, policySize):
	fileName = str(fileSize) + '-' + str(policySize)
	file = open("combineTime", "r")
	line = file.readline()
	totalTime = 0.0
	totalCount = 0
	while line:
		pattern = re.compile(fileName + '-[0-9]{1,2}:(.*)\n')
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
			decTime = getDecTime(fileSize, policySize)
			print fileName, '----totalTime(s):', totalTime, '----decTime(us):', decTime, '---rate:', (decTime / 10000) / totalTime, '%\n'
	

if __name__ == '__main__':
	if isCorrect():
		timeCombine()
		printRate()
