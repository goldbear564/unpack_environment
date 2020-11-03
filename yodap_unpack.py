import immlib
import random
import os
import pefile
import ctypes
from time import sleep

class SEC:
	def __init__(self,sec_name, sec_enp,final_enp,sec_start,sec_size):
		self.sec_name=sec_name
		self.sec_enp=sec_enp
		self.final_enp=final_enp
		self.sec_start=sec_start
		self.sec_size=sec_size
		self.sec_str=""
		self.sec_end=self.sec_start+self.sec_size
	
	def sec_print(self,imm):
		imm.log("section name : %s" % self.sec_name)
		imm.log("section entropy : %s" % self.sec_enp)
		imm.log("section final entropy : %s" % self.final_enp)
		imm.log("section start address : 0x%08X" % self.sec_start)
		imm.log("section size : 0x%08X" % self.sec_size)
		imm.log("section end : 0x%08X" % self.sec_end)
		imm.log("")


def Poly_ReturnDW(imm, Value):
	I=random.randint(1,3)
	if I==1:
		if random.randint(1,2)==1:
			#7 bytes
			return imm.assemble("Sub EAX, EAX\n Add EAX, 0x%08X" % Value)
		else:
			#7 bytes
			return imm.assemble("Sub EAX, EAX\n Sub EAX, -0x%08X" % Value)
	if I==2:
		#6 bytes
		return imm.assemble("Push 0x%08X\n Pop EAX\n" % Value)
	if I==3:
		if random.randint(1,2)==1:
			#7 bytes with optimized instructions
			return imm.assemble( "XChg EAX, EDI\n DB 0xBF\n DD 0x%08x\n XChg EAX, EDI" % Value )
		else:
			#8 bytes not optimized
			return imm.assemble( "XChg EAX, EDI\n Mov EDI, 0x%08x\n XChg EAX, EDI" % Value )
			
def Poly_Return0(imm):
	#Write poly instructions to patch a simple EAX on API
	I=random.randint(1,4)
	if I==1:
		#2 bytes Case
		return imm.assemble("Sub EAX, EAX")
	if I==2:
		if random.randint(1,2)==1:
			#6 bytes Case
			return imm.assemble("Push 0\n Pop EAX")
		else:
			#3 bytes Case
			return imm.assemble("DB 0x6A, 0x00\n Pop EAX")
	if I==3	:
		#4 bytes Case
		return imm.assemble("XChg EAX, EDI\n Sub EDI, EDI\n XChg EAX, EDI")
	if I==4:
		return Poly_ReturnDW(imm, 0)

def Patch_isdebuggerpresent(imm):
	isdebuggerpresent=imm.getAddress("kernelBA.IsDebuggerPresent")
	
	if(isdebuggerpresent<=0):
		imm.log("No IsDebuggerPresent")
		return
	imm.log("IsDebuggerPresent Address is 0x%08X" % isdebuggerpresent)
	imm.log("Patching IsDebuggerPresent")
	code = imm.assemble("DB 0x64\n Mov EAX,DWORD PTR DS:[18]") + Poly_Return0(imm) + imm.assemble("ret")
	while len(code) > 0x0E:
		code=imm.assemble("DB 0x64\n Mov EAX, DWORD PTR DS:[18]") + Poly_Return0(imm) + imm.assemble("ret")
	imm.writeMemory(isdebuggerpresent,code)
	
def Patch_checkremotedebuggerpresent(imm):
	addr=imm.getAddress("kernel32.CheckRemoteDebuggerPresent")
	if(addr<=0):
		imm.log("No CheckRemoteDebuggerPresent")
		return
		
	imm.log("CheckRemoteDebuggerPresent Address is 0x%08X" % addr)
	imm.log("Patching CheckRemoteDebuggerPresent",address=addr)
	imm.writeMemory(addr,imm.assemble("\
		Mov  EDI,EDI         \n \
		Push EBP             \n \
		Mov  EBP, ESP        \n \
		Mov  EAX, [EBP + C]  \n \
		Push 0               \n \
		Pop  [EAX]           \n \
		Xor  EAX, EAX        \n \
		Pop  EBP             \n \
		Ret  8               \
	"))
	
def getpid(s):
	im='"IMAGENAME eq %s"'%s
	cmd="tasklist /V /FI %s"%im
	s=os.popen(cmd).read()
	
	pid=""

	i=491  ## really bad magic number
	while True:
		pid=pid+s[i]
		if s[i+1]==' ':
			break
		i+=1
	
	return int(pid)

def Patch_zwqueryinformationprocess_processdebugport(imm):
	addr = imm.getAddress("ntdll.ZwQueryInformationProcess")
	if(addr<=0):
		imm.log("No ZwQueryInformationProcess to patch")
		return
	imm.log("ZwQueryInformationProcess(ProcessDebugPort) address is 0x%08X" % addr,address=addr)
	imm.log("Patching ZwQueryInformationProcess(ProcessDebugPort)")
	Patched=False
	
	# Scan Api and get size of first 2 instructions ..
    # On Win2k SysCall starts with Mov EAX, xxxxxxxx\n Lea EDX, [ESP + 4] ..
    # On WinXP, Win2k3 + Vista, SysCall always starts with Mov EAX, xxxxxxxx\n MOV EDX, 0x7FFE0300 ..
	a=0
	s=0
	while a<2:
		a+=1
		s += imm.disasmSizeOnly(addr + s).opsize
		#imm.log("a : 0x%08X || s : 0x%08X" % (a,s))
	
	#Check if already patched
	code_to_patch = imm.readMemory(addr,1) + imm.assemble("DD 0x12345678") + imm.readMemory(addr+5,1)
	#imm.log("%s" % code_to_patch)
	if code_to_patch == imm.assemble("Push 0x12345678\n Ret"):
		imm.log("already patched")
		#Maybe Found a push jump
		Patched=True
		#Get address of where it point to go
		a=imm.readLong(addr+1)
		#Get length of the 2 instructions before patch
		b=0
		s=0
		while b<2:
			b+=1
			s+=imm.disasmSizeOnly(a+s).opsize
	#if not patched, allocate some memory for patch code
	if Patched == False:
		#Allocate memory for hook the code
		a=imm.remoteVirtualAlloc(size=0x1000)
		#write 2 instructions from api to allocate memory
		imm.writeMemory(a,imm.readMemory(addr,s))
	
	 #If ProcessInformationClass = ProcessDebugPort then return 0 in
	 #ProcessInformation; else call ZwQueryInformationProcess as normal ..
	patch_code = "\
		Cmp    DWord [ESP + 8], 7      \n \
		DB     0x74, 0x06              \n \
		                               \n \
		Push   0x%08X                  \n \
		Ret                            \n \
		                               \n \
		Mov    EAX, DWord [ESP + 0x0C] \n \
		Push   0                       \n \
		Pop    [EAX]                   \n \
		Xor    EAX, EAX                \n \
		Ret    14                      \n \
	" %(addr+s)
	
	#Patch the code in allocated mem after original first 2 instructions
	imm.writeMemory(a+s, imm.assemble(patch_code))
	#imm.log("(addr + s) is : 0x%08X" % (addr+s))
	#if not patched, write Push JMP to redirect Api to patch code
	if Patched==False:
		imm.writeMemory(addr, imm.assemble("Push 0x%08X\n Ret" % a))

def Patch_zwqueryinformationprocess_processdebugobject(imm):
	addr = imm.getAddress("ntdll.ZwQueryInformationProcess")
	if(addr<=0):
		imm.log("No ZwQueryInformationProcess to patch")
		return
	imm.log("Patch_zwqueryinformationprocess_processdebugobject address is 0x%08X" % addr)
	imm.log("Patching ZwQueryInformationProcess")
	addr2=addr+12
	imm.log("addr2 is : 0x%08X" % addr2)
	patch_code = "RETN 14\n"
	#patch_code="JMP 0x%08X\n"%addr2
	test1=imm.disasmSizeOnly(addr).opsize
	imm.log("addr size is : 0x%08X" % test1)
	imm.writeMemory(addr,imm.assemble(patch_code))
	test1=imm.disasmSizeOnly(addr2).opsize
	imm.log("addr2 size is : 0x%08X" % test1)

def Patch_PEB(imm):
	PEB=imm.getPEBAddress()
	
	if PEB==0:
		imm.log("NO PEB to Patch")
		return
	imm.log("Pathcing PEB.IsDebugged", address=PEB+0x02)
	imm.writeMemory(PEB+0x02,imm.assemble("db 0"))
	
	a=imm.readLong(PEB+0x18) #HEAP Address
	a+=0x40
	imm.log("Patching PEB.ProcessHeap.Flag", address=a)
	imm.log("address is 0x%08X" % a)
	imm.writeLong(a,0x02)
	
	imm.log("Patching PEB.NtGlobalFlag",address=PEB+0x68)
	imm.writeLong(PEB+0x68,0)
	
	#a=imm.readLong(PEB+0x0C)
	#imm.log("Patching PEB.LDR_DATA",address=a)
	
	#while a!=0:
	#	a+=1
	#	try:
	#		b=imm.readLong(a)
	#		c=imm.readLong(a+4)
			
	#		if(b==0xFEEEFEEE) and (c==0xFEEEFEEE):
	#			imm.writeLong(a,0)
	#			imm.writeLong(a+4,0)
	#			a+=7
	#			
	#	except:
	#		break
	a=imm.readLong(PEB+0x18)
	a+=0x44
	imm.log("Patching PEB.ProcessHeap.ForceFlags",address=a)
	imm.log("address is 0x%08X" % a)
	imm.writeLong(a,0x0)
	
	

def Patch_PEB2(imm):
	PEB=imm.getPEBAddress()
	
	if PEB==0:
		imm.log("NO PEB to Patch")
		return
	a=imm.readLong(PEB+0x18) #HEAP Address
	a+=0x40
	imm.log("Patching PEB.ProcessHeap.Flag", address=a)
	imm.log("address is 0x%08X" % a)
	#imm.writeLong(a,0x02)


	a=imm.readLong(PEB+0x18)
	a+=0x44
	imm.log("Patching PEB.ProcessHeap.ForceFlags",address=a)
	imm.log("address is 0x%08X" % a)
	#imm.writeLong(a,0x0)

def Patch_zwqueryinformationprocess(imm):
	addr = imm.getAddress("ntdll.ZwQueryInformationProcess")
	if(addr<=0):
		imm.log("No ZwQueryInformationProcess to patch")
		return
	imm.log("ZwQueryInformationProcess address is 0x%08X" % addr,address=addr)
	a=0
	s=0 
	while a<3:
		a+=1
		s += imm.disasmSizeOnly(addr + s).opsize
		imm.log("a : 0x%08X || s : 0x%08X" % (a,s))
	Code=imm.assemble("NOP")*s
	imm.writeMemory(addr,Code)

def Patch_getcurrentrocessid(imm):
	addr=imm.getAddress("kernelba.GetCurrentProcessId")
	if(addr<=0):
		imm.log("No kernel32.GetCurrentProcessId to patch")
		return
	imm.log("kernel32.GetCurrentProcessId address is 0x%08X" % addr,address=addr)
	
	'''opcode=imm.disasm(addr)
	if(opcode.isJmp()):
		jmpAddr=opcode.getJmpAddr()
		imm.log("jmpAddr is : 0x%08X" % jmpAddr)
		next_opcode=imm.disasm(jmpAddr)
		if(next_opcode.isJmp()):
			jmpAddr=next_opcode.getJmpAddr()
			imm.log("next dst is : 0x%08X" % jmpAddr)'''
			
	s=imm.disasmSizeOnly(addr).opsize
	#imm.log("%s" % Code)
	a=0	
	whole_s=0
	cur_s=[]
	while a<2:
		a+=1
		cur_s.append(imm.disasmSizeOnly(addr + whole_s).opsize)
		whole_s += imm.disasmSizeOnly(addr + whole_s).opsize
		
		imm.log("a : 0x%08X || whole_s : 0x%08X || cur_s : 0x%08X" % (a,whole_s,cur_s[a-1]))
		if a==1:
			pid=getpid("ImmunityDebugger.exe")
			#Code=imm.assemble("Mov EAX,%x\n NOP"%pid)
			Code=imm.assemble("Mov EAX,0x%08X"%pid)
			while len(Code) < cur_s[a-1]:
				Code+=imm.assemble("NOP")	
			imm.writeMemory(addr,Code)
		elif a==2:
			imm.log("a==2")
			b=0
			Code=imm.assemble("NOP")*cur_s[a-1]
			imm.writeMemory(addr+cur_s[a-2],Code)
	#Code=imm.assemble("NOP")*(s+1)
	#imm.writeMemory(addr,Code)

def Patch_blockinput2(imm):
	addr=imm.getAddress("user32.BlockInput")
	#addr=0x598549
	if(addr<=0):
		imm.log("No user32.BlockInput to patch")
		return
	imm.log("user32.BlockInput address is 0x%08X" % addr,address=addr)
	a=0
	s=0 
	while a<3:
		a+=1
		s += imm.disasmSizeOnly(addr + s).opsize
	Code=imm.assemble("NOP")*s
	imm.writeMemory(addr,Code)
	imm.deleteBreakpoint(addr)
	#imm.setBreakpoint(addr+s)
	return addr+s
	
def Patch_Findwindow(imm):
	tag_list=['A','W','ExA','ExW']
	for tag in tag_list:
		
		retval=0x08
		if 'Ex' in tag:
			retval=0x10
		addr=imm.getAddress("user32.FindWindow%s" % tag)
		imm.log("user32.FindWindow%s addr: 0x%08X" % (tag,addr))
		if(addr<=0):
			imm.log("There's no FindWindow%s api" % tag)
			return
		cnt=0               #p
		op=imm.disasm(addr) #d 
		op_tmp=op           #l
		dis=""              #dis
		call=False
		
		while cnt<100:
			if op.getDisasm()=="POP EBP":
				dis=op_tmp.getDisasm()
				cnt-=op_tmp.getSize()
				if op_tmp.isCall():
					call=True
					break
				dis=op_tmp.getDisasm()
				break
			if op.getDisasm()=="RETN":
				if op_tmp.isPush():
					imm.log("FindWindow%s already patch" % tag)
					return
			cnt+=op.getSize()
			op_tmp=op
			op=imm.disasm(addr+cnt)
		
		imm.log("Patching FindWindow%s" % tag)
		HookMem = imm.remoteVirtualAlloc(size=0x1000)
		HookCode = imm.assemble("Push 0x%08X\n Ret" % HookMem)
		if call == True:
			a = op_tmp.getJmpAddr()
			a = ((a - HookMem) - 5)
			dis = ("DB 0xE8\n DD 0x%08X" % a)
		#ImmHWnd = ctypes.windll.LoadLibrary("User32.DLL").FindWindowW("ID", 0)
		PatchCode = " \
			%s                          \n\
			Xor     EAX, EAX            \n\
			Pop     EBP                 \n\
			Ret     0x%02X              \n\
			" % (dis, retval)
		imm.writeMemory(HookMem, imm.assemble(PatchCode))
		imm.writeMemory(addr + cnt, HookCode)
	return

def setMemBreakpoint2(imm,sec_list,section_name, type, size=4):
        """
            Modifies or removes a memory breakpoint.

            @type  sec_list: List of SEC class
            @param sec_list: SEC class list which has section information

            @type  sec_name: String
            @param sec_name: Section name of MemorkBreakPoint 

            @type  type: DWORD
            @param type: Type of Memory Breakpoint (READ/WRITE/SFX)

            @type  size: DWORD
            @param size: (Optional, Def: 4) Size of Memory Breakpoint
            """
        #imm.log("test")
        for sec in sec_list:
            if sec.sec_name==section_name:
                imm.log("section name : %s" % sec.sec_name)
                for i in range(sec.sec_start,sec.sec_end):
                    a=imm.setMemBreakpoint(i,type)
        #return debugger.set_mem_breakpoint(flags, addr, size)


def main(args):
	imm=immlib.Debugger()
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe=pefile.PE(path)
	filename=os.path.basename(path)
	section_list=[]
	name_list=[]
	a=0
	for section in pe.sections:
		sec_name=section.Name.strip("\x00")
		if sec_name=="":
			sec_name=str(a)
			a+=1
		sec_enp=section.get_entropy()
		final_enp=sec_enp
		name_list.append(sec_name)
		sec_start=pe.OPTIONAL_HEADER.ImageBase+section.VirtualAddress
		sec_size = section.Misc_VirtualSize
		imm.log("section : %s || start addr : 0x%08X || size : 0x%08X" % (sec_name,sec_start, sec_size))
		section_list.append(SEC(sec_name,sec_enp,final_enp,sec_start,sec_size))

	#for i in section_list:
		#i.sec_print(imm)
	Patch_Findwindow(imm)
	
	Patch_getcurrentrocessid(imm)
	bpaddr=Patch_blockinput2(imm)
	Patch_PEB(imm)
	Patch_isdebuggerpresent(imm)
	
	#setMemBreakpoint2(imm,section_list,"0","R|W")
	#imm.run()
	#a=imm.setMemBreakpoint(0x41DFFA,"R|W")
	#imm.run()
	
	
	Patch_checkremotedebuggerpresent(imm)
	#Patch_PEB(imm)
	#Patch_zwqueryinformationprocess(imm)
	Patch_zwqueryinformationprocess_processdebugport(imm)
	#sleep(1)
	#imm.run()
	#imm.stepOver()
	#sleep(2)
	#imm.run()
	#imm.stepOver()
	imm.setMemBreakpoint(section_list[0].sec_start,"S",section_list[0].sec_size)
	#imm.manualBreakpoint(section_list[0].sec_start,0x71,0,'fixed')
	imm.run()
	
	#sleep(1)
	#imm.run()
	#sleep(1)
	#imm.run()
	#sleep(1)
	#imm.run()
	#sleep(1)
	#imm.setHardwareBreakpoint(bpaddr)
	#imm.run(bpaddr)
	#imm.run(bpaddr)
	
	
	#Patch_zwqueryinformationprocess_processdebugobject(imm)
	#Patch_zwqueryinformationprocess_processdebugobject(imm)
	
	#imm.run(bpaddr)
	#a=imm.setMemBreakpoint(0x41DFFA,"R|W")
	#imm.log("a is %s" %  a)
	#imm.run()
	
