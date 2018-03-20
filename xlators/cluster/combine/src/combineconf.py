#!/usr/bin/env python

import os, sys, string
import bsddb, time

IOaddrFile="./IOaddr"
confile="./combine.vol"

MAX_IO=248;

def usage():
	 print "Usage:\n\tcombineconf.py -s [ionodelist]";
def prepare():
	try:
		os.stat(IOaddrFile);
	except:
		#print "JJH create default table";
		create_io_table();
	try:
		os.stat(confile);
	except:
		print "Create config file[%s]"%confile
	else:
		os.unlink(confile)

def create_io_table():
	ioDB=bsddb.btopen(IOaddrFile,'c');
	for i in range(MAX_IO):
		ioName="IO" + "%03d"%i;
		ipaddr="21.0.0." + "%d"%(i+1);
		#print ioName,ipaddr;	
		ioDB[ioName]=ipaddr;
	ioDB.close();

def write_element_with_thread(f,ioName,ipaddr):
	brickName = ioName + "_brick"
	f.write("volume ")
	f.write(brickName)
        f.write("\ntype protocol/client")
        f.write("\noption transport-type ib-verbs/client")
        f.write("\noption ping-timeout 110")
        f.write("\noption remote-port 8200")
        f.write("\noption remote-host ")
	f.write(ipaddr)
	f.write(" # IP address of the remote brick")
        f.write("\noption remote-subvolume bricklocal  # name of the remote volume")
	f.write("\nend-volume\n\n")

	f.write("volume ")
	f.write(ioName)
        f.write("\ntype performance/sw-threads")
        f.write("\noption thread-count 2")
        f.write("\nsubvolumes  ")
	f.write(brickName)
	f.write("\nend-volume\n\n")

def write_element(f,ioName,ipaddr):
	f.write("volume ")
	f.write(ioName)
        f.write("\ntype protocol/client")
        f.write("\noption transport-type ib-verbs/client")
        f.write("\noption ping-timeout 110")
        f.write("\noption remote-port 8200")
        f.write("\noption remote-host ")
	f.write(ipaddr)
	f.write(" # IP address of the remote brick")
        f.write("\noption remote-subvolume bricklocal  # name of the remote volume")
	f.write("\nend-volume\n\n")
def write_conf(f,nid,have_thread):
	ioDB=bsddb.btopen(IOaddrFile,'r');
	ioName="IO" + "%03d"%nid;
	ipaddr = ioDB[ioName];
	if ( have_thread ):
		write_element_with_thread(f,ioName,ipaddr)
	else :
		write_element(f,ioName,ipaddr)
	ioDB.close()

def write_end(f,nlist):
	f.write("volume cmb\n")
        f.write("type cluster/combine\n")
        f.write("subvolumes ")
	for nid in nlist:
		ioName="IO" + "%03d"%nid;
		f.write(" ")
		f.write(ioName)
	f.write("\nend-volume\n")
	
if __name__ == "__main__":
	if (len(sys.argv)!=3):
		usage();
        	sys.exit(1)
	nodelist = sys.argv[2]
	nodelist = nodelist.split(',')
        pnode = []
        for k in nodelist:
                if k.find('-') != -1:        # we have found the '-'
                        idx = k.find('-')
                        node1 = k[:idx]
                        node2 = k[idx+1:]
                        for node in range(eval(node1),eval(node2)+1):
                                pnode.append(int(node))
                else:
                        pnode.append(eval(k))
	#print pnode;
	prepare();
	F=open(confile, "w")
	for io in pnode:
		#print io
		#write_conf(F,io,False)
		write_conf(F,io,True)
	write_end(F,pnode)
	F.close()
