import immlib
import random
import os
import pefile
import math
import array
import ctypes

def compare_Sec(temp):
	#imm.log("")
	imm.log("[Entropy] Entropy Calculate of each Sections")
	#for a in section_enp.keys():
		#imm.log(a)
	print_flag=True
	
	for i in section_list:
		#imm.log("i is : %s" % i)
		a = section_enp[i] - temp[i] 
		if (a >=0.01) or (a <=-0.01):
			imm.log("[Entropy] %s(%s) entropy changes to %s " % (i,section_enp[i], temp[i]))
			section_enp[i]=temp[i]
			imm.log("[Entropy] OEP Changes")
			print_flag=False
			
		else:
			imm.log("[Entropy] %s(%s) Not changes." % (i, temp[i]))
			if print_flag:
				imm.log("[Entropy] OEP Not Changes")
	#imm.log("")
	return 
	
def get_Section(Addr):
	for i in section_list:
		#imm.log("[get Section] section : %s" % i)
		#imm.log("[get Section] Dst Addr : 0x%08X" % Addr)
		#imm.log("[get Section] section_start : 0x%08X" % section_start[i])
		#imm.log("[get Section] section_end : 0x%08X" % section_end[i])
		if section_start[i]<=Addr and section_end[i]>Addr:
			return i
	return False

def entropy(str):
	if len(str)==0:
		return 0.0
	occurences = array.array('L', [0]*256)
	i=0
	for x in str:
		if(i==len(str)):
			break
		a=str[i:i+2]
		#imm.log("i is : %d " % i + "str is : %s " % a + "length is : %d" % len(str))
		b=int(a,16)
		occurences[b]+=1
		i+=2
	entropy = 0
	for x in occurences:
		if x:
			p_x = float(x)/(len(str)/2)
			entropy-=p_x*math.log(p_x,2)
	return entropy
	
	
def sec_entropy(imm):
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe=pefile.PE(path)
	filename=os.path.basename(path)
	#imml.log("filename is : %s" % filename)
	section_list2=[]
	section_list2=get_section_name(imm,section_list2)
	section_enp2={}
	section_str2={}
	section_start2={}
	section_end2={}
	count=0
	sec_blank_num=0
	sec_blank_num2=0
	for section in pe.sections:
		section_enp2[section_list2[count]]=section.get_entropy()
		section_str2[section_list2[count]]=""
		count+=1
	mem=imm.getMemoryPages()
	
	for a in mem.keys():
		i=0
		mempage_addr = imm.getMemoryPageByAddress(a)
		mempage_sec=mempage_addr.getSection()
		name=""
		if mempage_sec=="":
			mempage_sec=str(sec_blank_num2)
			sec_blank_num2+=1
		if(mempage_sec in section_list2 and mempage_addr.getOwner()==filename):
			section_start2[mempage_sec] = a
			section_end2[mempage_sec] = a+mempage_addr.getSize()
			section_str2[mempage_sec] = imm.readMemory(section_start2[mempage_sec],mempage_addr.getSize()).encode("hex")
			section_enp2[mempage_sec] = entropy(section_str2[mempage_sec])
	return section_enp2

def get_section_name(imm,section_list):
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe = pefile.PE(path)
	section_list_def=[]
	blank_num_def=0
	for section in pe.sections:
		name=""
		a=section.Name.split("\x00")[0]
		#for c in a[0]:
		#	if c.isalnum():
		#		name+=c
		if a!="":
			section_list_def.append(a)
		else:
			section_list_def.append(str(blank_num_def))
			blank_num_def+=1
		#imm.log("name : %s" % a )
	section_list=section_list_def
	return section_list


def unpack(imm):
	imm.stepOver()
	imm.stepOver()
	addr=imm.getRegs()['ESP']
	imm.setHardwareBreakpoint(addr, size=4)
	imm.run(addr)
	imm.run()
	#imm.stepOver()
	#imm.setpOver()


def main(args):
	imm=immlib.Debugger()
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe=pefile.PE(path)
	filename=os.path.basename(path)
	unpack(imm)
	sec_entropy_result=sec_entropy(imm)
	for sec in sec_entropy_result:
		imm.log("%s\'s entropy: %f" % (sec,sec_entropy_result[sec]))