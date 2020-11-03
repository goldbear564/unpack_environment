import immlib
import pefile
import math
import array
import os


imm=immlib.Debugger()
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
				imm.log("get Section error by address")
				imm.log("cur address is : 0x%08X" % curAddr)
				break
				#return "1"
			if(jmpAddr==0):
				imm.log("program end")
				break
				#return "2"
			elif (curAddr > section_end[curSection]):
				imm.log("program end 2")
				break
				#return "2"
			elif (jmpAddr>section_end[section_list[list_count-1]]):
				imm.log("jump to outside of file")
				break
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
				curAddr=imm.getRegs()['EIP']
				imm.log("")
				for j in range(0,list_count):
					imm.log("======== section to string=========")
					imm.log("start address : 0x%08X" % section_start[section_list[j]])
					MemPage_addr = imm.getMemoryPageByAddress(section_start[section_list[j]])
					pagesize=MemPage_addr.getSize()
					section_str[section_list[j]] = ""
					for i in range(0,pagesize):
						page_readMemory=imm.readMemory(section_start[section_list[j]]+i,1)
						section_str[section_list[j]] += page_readMemory.encode("hex")
					a = entropy(section_str[section_list[j]])
					if a-section_enp[section_list[j]] < - 0.01 or a-section_enp[section_list[j]] > 0.01:
						section_enp[section_list[j]] = a
						imm.log("")
						imm.log("section_enp changed")
					
				imm.log("")
				imm.log("curAddr after jump is : 0x%08X" % curAddr)
				
		else:
			curAddr+=opsize
		
	
	imm.log("OEP is 0x%08X" % OEP +" jump to 0x%08X" % OEP2)
	imm.log("")
	'''for i in range(0,list_count):
		imm.log("section : %s" % section_list[i])
		imm.log("section string")
		#imm.log(section_str[section_list[i]])
		imm.log("section entropy")
		#imm.log("%f" % section_enp[section_list[i]])
		imm.log("==============")
	'''
if __name__=="__main__":
	print "This module is for use within Immunity Debugger only"