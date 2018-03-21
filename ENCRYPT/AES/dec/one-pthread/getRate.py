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
lineFlag = [0, 1, 3, 7, 15, 31, 63, 127, 255]

groupCount = 20

#计算行数是否正确
def isCorrect():
	file = open("time_result_dec", "r")
	lineCount = len(file.readlines())
	print "getline:", lineCount

	count = 0	
	for fileSize in fileSizes:
		count += (fileSize / 128)
	print "should get:", count * groupCount

	if count*groupCount == lineCount:
		return 1
	else:
		return 0



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

def getDecTime(fileSize, lines):
	count = fileSize / 128

	index = fileSizes.index(fileSize)
	
	totalTime = 0.0
	totalCount = 0
	for line in lines[lineFlag[index]*groupCount: lineFlag[index+1]*groupCount]:
		pattern = re.compile('(.*):(.*)\n')
		searchObj = re.search(pattern, line)
		if searchObj:
			totalTime += float(searchObj.group(2))
			totalCount += 1
	print fileSize,"conculate",totalCount,"lines"

	return totalTime / groupCount

def printRate():
	file = open("time_result_dec", "r")
	lines = file.readlines()

	for fileSize in fileSizes:
		totalTime = getTotalTime(fileSize)
		
		decTime = getDecTime(fileSize, lines)
		print fileSize, '----totalTime(s):', totalTime, '----decTime(us):', decTime, '---rate:', (decTime / 10000) / totalTime, '%\n'

if __name__ == '__main__':
	if isCorrect():
		printRate()
