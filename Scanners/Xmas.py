#!/usr/bin/env python

import optparse 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import randint
from sys import exit

class XMASCAN(object):
  def __init__(self):
    self.src=args.src
    self.dest=args.dst
    self.srcp=args.sport
    self.rand=args.rand
    try:
      if args.dport.split('-')[1]!=None:
        self.dstp=int(args.dport.split('-')[0])
        self.pf=int(args.dport.split('-')[1])
    except:
      if args.dport==None:
        self.dstp=80
      else:
        self.dstp=int(args.dport)
      self.pf=self.dstp+1

  def header(self):
    print "/////////////////////////////////////////////////"
    print "///////////////////// db43 //////////////////////"
    print "/////////////////////////////////////////////////" 
    print "///////////////// CW - Lojistik /////////////////"
    print "/////////////////////////////////////////////////"
    print "///////////////////// 2015 //////////////////////"
    print "/////////////////////////////////////////////////\n"

  def calctime(self):
    print "[!] Calculating timeout for scan"
    tic=time.time()
    sr1(self.IPhead()/ICMP() ,verbose=False)
    toc=time.time()+1
    print "[!] Sending crafted packet"
    return toc-tic    

  def IPhead(self):
    if self.src:
      IPh=IP(src=self.src ,dst=self.dest)
    else:
      IPh=IP(dst=self.dest)
    return IPh

  def TCPhead(self):
    if self.rand=="1":
      src=random.randint(1 ,65535)
    else:
      src=int(self.srcp)
    try:
      if args.dport.split('-')[1]!=None:
        args.dport=args.dport.split('-')[0]
        args.pf=args.dport.split('-')[1]
    except:
      if args.dport==None:
        args.dport=80
        src=self.srcp
    TCPh=TCP(flags="FPU" ,dport=self.dstp ,sport=src)
    return TCPh

  def craft_analyse(self):
    self.header()
    print "[!] Don't use IP spoofing outside of your subnet"
    data=Raw(load="\x64\x62\x34\x33\x63\x77")
    while self.dstp<self.pf: 
      pact=self.IPhead()/self.TCPhead()/data
      ret=sr1(pact ,timeout=self.calctime() ,verbose=False)
      try:
        ret.flag=ret.sprintf("%TCP.flags%")
        if ret.flag=="RA" or ret.flag=="R":
          print "[-] TCP port: "+str(self.dstp)+" is closed"
      except:
          print "[+] TCP port: "+str(self.dstp)+" is open|filtered"
      self.dstp +=1 


if __name__=="__main__":
  parser=optparse.OptionParser()
  parser.add_option("-s" ,"--src" ,dest="src" ,type="string",
  help="Source IP adress default is yours " ,metavar="IP")
  parser.add_option("-d" ,"--dst" ,"--destination" ,dest="dst" ,type="string",
  help="Adress that you want to scan" ,metavar="IP")
  parser.add_option("-p" ,"--sport" ,"--lport" ,dest="sport" ,type="string",
  help="Source port adress default is 20")
  parser.add_option("-c" ,"--dport" ,"--rport" ,dest="dport" ,type="string",
  help="Destination port adress default is 80 example usage:21 ,21-80 ")
  parser.add_option("-r" ,"--random" ,dest="rand" ,type="string",
  help="Randomize source port numbers everytime default: 0 for randomizing enter: 1 ")
  args ,opts=parser.parse_args()
  if args.dst==None:
    parser.print_help()
    exit()
  if args.sport==None and args.rand==None:
    args.sport=20
  elif args.rand=="1":
    args.sport=20
  
  XMASCAN().craft_analyse()
