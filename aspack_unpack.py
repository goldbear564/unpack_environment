import immlib
import pefile
import math
import array
import os


imm=immlib.Debugger()
def get_stack():
	curesp = imm.getRegs()['ESP']
	test = imm.readMemory(curesp,4).encode("hex")
	imm.log("[get_stack] data in stack : %s" % test)
	stack=ltob(test)
	imm.log("[get_stack] stack string : %s" %stack)
	stack=int(stack,16)
	imm.log("[get_stack] stack hex is : 0x%08X" % stack)
	return stack
	
def ltob(str):
	#imm.log("str is : %s " % str)
	test2=""
	while(True):
		l=len(str)
		#imm.log("test[-2:0] is %s" % str[-2:])
		test2+=str[-2:]
		str=str[0:l-2]
		#imm.log("lef str is : %s" % str)
		if(len(str)==0):
			break
	
	return test2
	
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

def main(args):
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe = pefile.PE(path)
	filename = os.path.basename(path)
	imm.log("%s" % path)
	imm.log("basename : %s" % filename)
	ImageBase = pe.OPTIONAL_HEADER.ImageBase
	imm.log("image base is :  0x%08X" % ImageBase)
	imm.log("SizeofHeaders : 0x%08X" % pe.OPTIONAL_HEADER.SizeOfHeaders)
	imm.log("section alignment : 0x%08X" % pe.OPTIONAL_HEADER.SectionAlignment)
	imm.log("EIP : 0x%08X" % imm.getRegs()['EIP'])
	first_addr = imm.getRegs()['EIP']
	section_list=[]
	section_enp={}
	section_str={}
	section_start={}
	section_end={}
	final_enp={}
	OEP=0
	OEP2=0
	list_count=0
	passing=0
	jmpcount=0
	multiL = False
	for section in pe.sections:
		section_list.append(section.Name.strip("\x00"))
		section_enp[section_list[list_count]]=section.get_entropy()
		final_enp[section_list[list_count]]=section_enp[section_list[list_count]]
		section_str[section_list[list_count]]=""
		list_count+=1
	
	mem = imm.getMemoryPages()
	for a in mem.keys():
		mempage_addr = imm.getMemoryPageByAddress(a)
		mempage_sec = mempage_addr.getSection()
		if(mempage_sec in section_list and mempage_addr.getOwner() == filename):
			#imm.log("%s" %mempage_sec)
			#imm.log("%s" % mempage_addr.getOwner())
			#imm.log("0x%08X" % a)
			#imm.log("======")
			section_start[mempage_sec] = a
			section_end[mempage_sec] = a+mempage_addr.getSize()
		
	for i in range(0,list_count):
		imm.log("section :%s" % section_list[i])
		imm.log("section start  addr : 0x%08X" % section_start[section_list[i]])
		imm.log("section_end addr : 0x%08X" % section_end[section_list[i]])
		imm.log("first entropy : %f" % section_enp[section_list[i]])
		imm.log("")
		
	first_jmp = imm.disasm(first_addr)
	
	if(first_jmp.isJmp() or first_jmp.isConditionalJmp()):
		imm.log("meet jump at firstAddr")
		imm.stepOver()
	else:
		imm.stepOver()
		#imm.run(firstAddr)
	curAddr = imm.getRegs()['EIP']
	
	imm.log("**********Analysis Start**********")
	while(True):
		opcode = imm.disasm(curAddr)
		opsize = opcode.getOpSize()
		
		if(opcode.isJmp() or opcode.isConditionalJmp()):
			jmpAddr = opcode.getJmpAddr()
			curMempage = imm.getMemoryPageByAddress(curAddr)
			jmpMempage = imm.getMemoryPageByAddress(jmpAddr)
			try:
				curSection = curMempage.getSection()
				jmpSection = jmpMempage.getSection()
			except:
				imm.log("")
				imm.log("[try get curSection]get Section error by address at : 0x%08X" % curAddr)
				imm.log("[try get jmpSection]get Section error by jmpaddress at : 0x%08X" % jmpAddr)
				curAddr+=opsize
				continue
				#break
				#return "1"
			if(jmpAddr==0):
				#imm.log("program end")
				curAddr+=opsize
				continue
				#break
				#return "2"
			elif (curAddr > section_end[curSection]):
				imm.log("Section end 2")
				curAddr+=opsize
				break
				#return "2"
			elif (jmpAddr>section_end[section_list[list_count-1]]):
				imm.log("jump to outside of file")
				if passing==0:
					imm.log("passing increase at 0x%08X" % curAddr)
					curAddr+=opsize
					#break
					continue
				else:
					passing+=1
					break
				if(passing==1):
					return ("jump to outside of file at 0x%08X" % curAddr)
					
					#return "3"
				#return "3"
			elif (jmpSection==curSection):
				#imm.log("same section")
				curAddr = curAddr+opsize
			else:
				imm.log("JUMP to different Section : %s" % jmpSection)
				imm.log("JUMP to 0x%08X" % jmpAddr)
				imm.log("FROM 0x%08X" % curAddr)
				OEP=curAddr
				OEP2=jmpAddr
				imm.run(curAddr)
				imm.stepOver()
				jmpcount+=1
				curAddr=imm.getRegs()['EIP']
				imm.log("")
				for j in range(0,list_count):
					imm.log("======== section to string in JUM=========")
					imm.log("start address : 0x%08X" % section_start[section_list[j]])
					MemPage_addr = imm.getMemoryPageByAddress(section_start[section_list[j]])
					pagesize=MemPage_addr.getSize()
					section_str[section_list[j]] = imm.readMemory(section_start[section_list[j]],pagesize).encode("hex")
					#for i in range(0,pagesize):
					#	page_readMemory=imm.readMemory(section_start[section_list[j]]+i,1)
					#	section_str[section_list[j]] += page_readMemory.encode("hex")
					a = entropy(section_str[section_list[j]])
					if a-section_enp[section_list[j]] < - 0.01 or a-section_enp[section_list[j]] > 0.01:
						section_enp[section_list[j]] = a
						imm.log("")
						imm.log("section_enp changed")
				if(section_enp[jmpSection]<5.0 or section_enp[jmpSection]>6.85):
					continue
				else:
					break
				imm.log("")
				imm.log("curAddr after jump is : 0x%08X" % curAddr)
		
		elif(opcode.isRet()):
			if(opcode.getResult()=="RETN"):		
				imm.run(curAddr)
				imm.log("[main] get stack at 0x%08X" % curAddr)
				jmpAddr=get_stack()
				curMempage=imm.getMemoryPageByAddress(curAddr)
				jmpMempage=imm.getMemoryPageByAddress(jmpAddr)
				try:
					curSection = curMempage.getSection()
					jmpSection=jmpMempage.getSection()
				except:
					return "get section error from Memory Page"
				
				if(curSection in section_list and jmpSection in section_list and curSection!=jmpSection):
					imm.stepOver()
					if(imm.isAnalysed(imm.getRegs()['EIP'])== 1):
						imm.log("anal")
						imm.analyseCode(jmpAddr)
					imm.log("JUMP to different Section : %s" % jmpSection)
					imm.log("JUMP to 0x%08X" % jmpAddr)
					imm.log("FROM 0x%08X" % curAddr)
					OEP = curAddr
					OEP2=jmpAddr
					curAddr=imm.getRegs()['EIP']
					imm.log("")
					for j in range(0, list_count):
						imm.log("=====section to string in RET=====")
						imm.log("start address : 0x%08X" % section_start[section_list[j]])
						MemPage_addr = imm.getMemoryPageByAddress(section_start[section_list[j]])
						section_str[section_list[j]] = imm.readMemory(section_start[section_list[j]],MemPage_addr.getSize()).encode("hex")
						final_enp[section_list[j]] = entropy(section_str[section_list[j]])
						imm.log("section : %s" % section_list[j])
						imm.log("section 1st Entropy : %f" % section_enp[section_list[j]])
						imm.log("section cur Entropy : %f" % final_enp[section_list[j]] )
					if(final_enp[jmpSection]<5.0 or final_enp[jmpSection]>6.85):
						continue
					else:
						multiL = True
						break
					
					##entropy calc part
					
					imm.log("")
					imm.log("curAddr after jump is : 0x%08X" % curAddr)
					
				else:
					curAddr+=opsize
					continue
			else:
				curAddr+=opsize
				continue
		else:
			curAddr+=opsize

	imm.log("")
	
	for i in range(0,list_count):
		imm.log("section : %s" % section_list[i])
		imm.log("section string")
		imm.log(section_str[section_list[i]])
		imm.log("final section entropy : %f" % final_enp[section_list[i]])
		imm.log("==============")
	imm.log("OEP is 0x%08X" % OEP +" jump to 0x%08X" % OEP2)
		
if __name__=="__main__":
	print "This module is for use within Immunity Debugger only"