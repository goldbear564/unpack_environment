import immlib
import pefile
import math
import array
import os




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

def sec_entropy(imml):
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe=pefile.PE(path)
	filename=os.path.basename(path)
	#imml.log("filename is : %s" % filename)
	section_list2=[]
	section_list2=get_section_name(section_list2)
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
	mem=imml.getMemoryPages()
	
	for a in mem.keys():
		i=0
		mempage_addr = imml.getMemoryPageByAddress(a)
		mempage_sec=mempage_addr.getSection()
		name=""
		if mempage_sec=="":
			mempage_sec=str(sec_blank_num2)
			sec_blank_num2+=1
		if(mempage_sec in section_list2 and mempage_addr.getOwner()==filename):
			section_start2[mempage_sec] = a
			section_end2[mempage_sec] = a+mempage_addr.getSize()
			section_str2[mempage_sec] = imml.readMemory(section_start2[mempage_sec],mempage_addr.getSize()).encode("hex")
			section_enp2[mempage_sec] = entropy(section_str2[mempage_sec])
	return section_enp2

def get_section_name(section_list):
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
	
	
def main(args):
	global imm,section_list,section_enp,section_str,section_start, section_end, final_enp
	imm=immlib.Debugger()
	section_list=[]
	section_enp={}
	section_str={}
	section_start={}
	section_end={}
	final_enp={}
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe = pefile.PE(path)
	filename = os.path.basename(path)
	imm.log("%s" % path)
	imm.log("basename : %s" % filename)
	imm.log("EIP : 0x%08X" % imm.getRegs()['EIP'])
	first_addr = imm.getRegs()['EIP']
	OEP=0
	OEP2=0
	list_count=0
	passing=0
	cj_count=0
	multiL = False
	jmp_From = []
	jmp_To=[]
	cjmp_From=[]
	cjmp_To=[]
	retn_From=[]
	retn_To=[]
	blank_num=0
	blank_num2=0
	test_i=0
	section_list=get_section_name(section_list)
	for section_name in section_list:
		imm.log("section_name : %s" % section_name)
		
	for section in pe.sections:
		section_enp[section_list[list_count]]=section.get_entropy()
		final_enp[section_list[list_count]]=section_enp[section_list[list_count]]
		section_str[section_list[list_count]]=""
		list_count+=1
		test_i+=1
	'''
	mem=imm.getMemoryPages()
	for a in mem.keys():
		mempage_addr = imm.getMemoryPageByAddress(a)
		mempage_sec = mempage_addr.getSection()
		blank=False
		if mempage_sec=="":
			mempage_sec=str(blank_num)
			blank=True
		imm.log(mempage_sec)
		if(mempage_sec in section_list and mempage_addr.getOwner() == filename):
			imm.log("[mempage part] mempage_sec : |%s|" % mempage_sec )
			if blank:
				blank_num+=1
			
			section_start[mempage_sec] = a
			section_end[mempage_sec] = a+mempage_addr.getSize()
	'''
	mem=imm.getMemoryPageByOwner(filename)
	temp_list=[]
	for a in mem:
		temp_list.append(a.getBaseAddress())
		#imm.log("0x%08X" % a.getBaseAddress())
	temp_list.remove(min(temp_list))
	temp_list.sort()
	for t in temp_list:
		imm.log("0x%08X" % t)
		for a in mem:
			if a.getBaseAddress() == t:
				a_sec=a.getSection()
				a_base = a.getBaseAddress()
				blank=False
				if a_sec=="" and a_base in temp_list:
					a_sec=str(blank_num)
					blank=True
				if a_sec in section_list and a_base in temp_list:
					imm.log("[mempage part] mempage_sec : |%s|" % a_sec )
					if blank:
						blank_num+=1
					section_start[a_sec]=a.getBaseAddress()
					section_end[a_sec]=a.getBaseAddress() + a.getSize()
			else:
				continue
			

	for i in range(0,list_count):
		imm.log("section :|%s|" % section_list[i])
		imm.log("section start  addr : 0x%08X" % section_start[section_list[i]])
		imm.log("section_end addr : 0x%08X" % section_end[section_list[i]])
		imm.log("first entropy : %f" % section_enp[section_list[i]])
		imm.log("")
	
	first_jmp = imm.disasm(first_addr)
	
	if(first_jmp.isJmp() or first_jmp.isConditionalJmp()):
		imm.log("meet jump at firstAddr")
		imm.stepOver()
	#else:
	#	imm.stepOver()
	#	imm.run(firstAddr)
	curAddr = imm.getRegs()['EIP']
	imm.log("curAddr: 0x%08X" % curAddr)

	code_sec_start = imm.getModule(imm.getDebuggedName()).getCodebase()
	code_sec = ""
	for sec, start_addr in section_start.iteritems():
		if start_addr == code_sec_start:
			code_sec=sec
			break
	#if code_sec == "":
	#	return "CAN'T GET CODE SECTION"
	imm.log("code section is %s" % code_sec)
	imm.log("**********Analysis Start**********")
	#return 'ENDS'
	while(True):
		#imm.log("curAddr  is : 0x%08X" % curAddr)	
		opcode = imm.disasm(curAddr)
		opsize = opcode.getOpSize()
		if(opcode.isJmp()):
			if opcode.getResult()=="JMP EAX":
				imm.log("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
				jmpAddr=imm.getRegs()['EAX']
				imm.log("jmpAddr: 0x%08X" % jmpAddr)
				imm.log("curAddr: 0x%08X" % curAddr)
				#imm.run(jmpAddr)
				#break
			else:
				jmpAddr = opcode.getJmpAddr()
			imm.run(curAddr)
			curMempage = imm.getMemoryPageByAddress(curAddr)
			jmpMempage = imm.getMemoryPageByAddress(jmpAddr)
			curSection = get_Section(curAddr)
			jmpSection = get_Section(jmpAddr)
			imm.log("curSection: %s" % curSection)
			imm.log("jmpSection: %s" % jmpSection)
			if jmpSection==False:
				imm.log("[JMP]jmpSection: %s" % jmpSection)
				imm.log("[JMP]get jmpSection error at 0x%08X to 0x%08X" % (curAddr, jmpAddr))
				curAddr+=opsize
				continue
			else:
				imm.log("[JMP] Cur Addr : 0x%08X | Dst Addr : 0x%08X" % (curAddr, jmpAddr))
				imm.log("[JMP] Cur Section : %s | Dst Section : %s" % (curSection,jmpSection))
			if(curSection in section_list and jmpSection in section_list and curSection==jmpSection):
				'''SAME SECTION after JMP'''
				if curAddr in jmp_From or jmpAddr in jmp_To:
					curAddr+=opsize
					continue
				else:
					jmp_From.append(curAddr)
					jmp_To.append(jmpAddr)
				imm.stepOver()
				#imm.log("[JMP_check]JMP to 0x%08X FROM 0x%08X" %(curAddr,jmpAddr))
				##calc entropy
				curAddr = imm.getRegs()['EIP']
				temp=sec_entropy(imm)
				compare_Sec(temp)
				
			elif(curSection in section_list and jmpSection in section_list and curSection!=jmpSection):
				'''DIFF SECTION after JMP'''
				if curAddr in jmp_From or jmpAddr in jmp_To:
					curAddr+=opsize
					continue
				else:
					jmp_From.append(curAddr)
					jmp_To.append(jmpAddr)
				imm.stepOver()
				#imm.log("[Diff Section]JUMP to 0x%08X FROM 0x%08X" %(curAddr,jmpAddr))
				#imm.log("[Diff Section]JMP to %s Section" % jmpSection)
				##calc entropy
				temp=sec_entropy(imm)
				compare_Sec(temp)
				#curAddr = imm.getRegs()['EIP']
				break
		elif(opcode.isConditionalJmp()):
			imm.run(curAddr)
			jmpAddr = opcode.getJmpAddr()
			curMempage = imm.getMemoryPageByAddress(curAddr)
			jmpMempage = imm.getMemoryPageByAddress(jmpAddr)
			curSection = get_Section(curAddr)
			jmpSection = get_Section(jmpAddr)
			if jmpSection==False:
				imm.log("[CJMP]get jmpSection error at 0x%08X to 0x%08X" % (curAddr, jmpAddr))
				curAddr+=opsize
				continue
			else:
				#imm.log("[CJMP Destination's Section is %s/ address is 0x%08X" % (jmpSection, jmpAddr))
				imm.log("[CJMP] Cur Addr : 0x%08X | Dst Addr : 0x%08X" % (curAddr, jmpAddr))
				imm.log("[CJMP] Cur Section : %s | Dst Section : %s" % (curSection,jmpSection))
				
				
			if(curSection in section_list and jmpSection in section_list and curSection==jmpSection):
				'''SAME SECTION after CJMP'''
				if curAddr in cjmp_From or jmpAddr in cjmp_To:
					curAddr+=opsize
					continue
				else:
					cjmp_From.append(curAddr)
					cjmp_To.append(jmpAddr)
				imm.stepOver()
				imm.log("[CJMP to Same Section] CJUMP to 0x%08X FROM 0x%08X" % (jmpAddr,curAddr))
				##calc entropy
				curAddr = imm.getRegs()['EIP']
				temp = sec_entropy(imm)
				compare_Sec(temp)
				
			elif(curSection in section_list and jmpSection in section_list and curSection!=jmpSection):
				'''DIFF SECTION after CJMP '''
				if curAddr in cjmp_From or jmpAddr in cjmp_To:
					curAddr+=opsize
					continue
				else:
					cjmp_From.append(curAddr)
					cjmp_To.append(jmpAddr)
				imm.stepOver()
				#imm.log("CJMP to Diff Section(%s)" % jmpSection)
				curAddr = imm.getRegs()['EIP']
				##calc entropy
				temp=sec_entropy(imm)
				compare_Sec(temp)
				break
		elif(opcode.isRet()):
			if(opcode.getResult()=="RETN"):
				#imm.log("MEET RETN")
				imm.run(curAddr)
				jmpAddr=get_stack()
				curMempage=imm.getMemoryPageByAddress(curAddr)
				jmpMempage=imm.getMemoryPageByAddress(jmpAddr)
				jmpSection = get_Section(jmpAddr)
				if jmpSection==False:
					imm.log("[RETN]get jmpSection error at 0x%08X to 0x%08X" %(curAddr,jmpAddr))
					curAddr+=opsize
					continue
				else:
					#imm.log("RETN Destination's Section is %s/ address is 0x%08X" % (jmpSection, jmpAddr))
					imm.log("[RETN] Cur Addr : 0x%08X | Dst Addr : 0x%08X" % (curAddr, jmpAddr))
					imm.log("[RETN] Cur Section : %s | Dst Section : %s" % (curSection,jmpSection))
				if(curSection in section_list and jmpSection in section_list and curSection==jmpSection):
					'''SAME SECTION after RETN'''
					if curAddr in retn_From or jmpAddr in retn_To:
						curAddr+=opsize
						continue
					else:
						retn_From.append(curAddr)
						retn_To.append(jmpAddr)
					imm.stepOver()
					#imm.log("[RETN to Same Section] RETN to 0x%08X FROM 0x%08X" % (jmpAddr,curAddr))
					if(imm.isAnalysed(imm.getRegs()['EIP'])==1):
						imm.log("Analysed")
						imm.analyseCode(jmpAddr)
					curAddr = imm.getRegs()['EIP']
					##calc entropy
					temp=sec_entropy(imm)
					compare_Sec(temp)
				#elif(curSection in section_list and jmpSection in section_list and curSection!=jmpSection):
				elif (curSection!=jmpSection):
					'''DIFF SECTION after RETN'''
					if curAddr in retn_From or jmpAddr in retn_To:
						curAddr+=opsize
						continue
					else:
						retn_From.append(curAddr)
						retn_To.append(jmpAddr)
					imm.stepOver()
					if(imm.isAnalysed(imm.getRegs()['EIP'])==1):
						imm.log("Analysed")
						imm.analyseCode(jmpAddr)
					#imm.log("RETN to Diff Section(%s)" % jmpSection)
					temp=sec_entropy(imm)
					compare_Sec(temp)
					#curAddr = imm.getRegs()['EIP']
					break
				else:
					curAddr+=opsize
					continue
				imm.log("")
			else:
				curAddr+=opsize
				continue
		#elif(opcode.isCall()):
		#	imm.runTillRet()
		#	testaddr = imm.getRegs()['EIP']
		#	imm.log("test addr is 0x%08X" % testaddr)
		#	break
			#return 'here'
			
		else:
			curAddr+=opsize
	imm.log("**********Analysis End**********")
	imm.log("jmpAddr: 0x%08X" % jmpAddr)
	imm.run(jmpAddr)
	imm.log("")
	try:
		root_place = "C:\\Users\\nmlab\\Downloads\\" + filename.split(".")[0]+".txt"
		f=open(root_place,'w')
		
		for i in range(0,list_count):
			imm.log("section : %s" % section_list[i])
			data = "[" + section_list[i] + " Section's string]\n"
			f.write(data)
			imm.log("section string")
			imm.log(section_str[section_list[i]])
			data = section_str[section_list[i]]
			f.write(data)
			data="\n\n"
			f.write(data)
			imm.log("final section entropy : %f" % final_enp[section_list[i]])
			imm.log("==============")
		f.close()
	except:
		imm.log("fail to open file")
	imm.log("OEP IS 0x%08X(%s)" % (jmpAddr,get_Section(jmpAddr)))
	imm.log("Section jumped from 0x%08X(%s)" % (curAddr, get_Section(curAddr)))
	for i in section_list:
		imm.log("%s Section : %s" % (i, section_enp[i]))
	
	return '========================== ENDS =========================='
	
if __name__=="__main__":
	print "This module is for use within Immunity Debugger only"
	
