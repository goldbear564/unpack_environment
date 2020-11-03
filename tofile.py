import pefile
import immlib
import os
import binascii

imm=immlib.Debugger()

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
	path = imm.getModule(imm.getDebuggedName()).getPath()
	pe = pefile.PE(path)
	filename = os.path.basename(path)
	imm.log("%s" % path)
	imm.log("basename : %s" % filename)
	ImageBase = pe.OPTIONAL_HEADER.ImageBase
	imm.log("image base is :  0x%08x" % ImageBase)
	imm.log("SizeofHeaders : 0x%08x" % pe.OPTIONAL_HEADER.SizeOfHeaders)
	imm.log("section alignment : 0x%08x" % pe.OPTIONAL_HEADER.SectionAlignment)
	#imm.log("EIP : 0x%08x" % imm.getRegs()['EIP'])
	imm.log("")
	
	#if(After_Header % pe.OPTIONAL_HEADER.SectionAlignment != 0):	
	section_list = []
	section_list=get_section_name(section_list)
	section_str={}
	section_start={}
	section_end={}
	list_count=0
	blank_num=0
	for section in pe.sections:
		section_str[section_list[list_count]]=""
		list_count+=1
		
	mem=imm.getMemoryPageByOwner(filename)
	temp_list=[]
	for a in mem:
		temp_list.append(a.getBaseAddress())
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
	
	imm.log("")
	for j in range(0,list_count):
		imm.log("-----section to string------")
		imm.log("start address : 0x%08X" % section_start[section_list[j]])
		MemPage_addr = imm.getMemoryPageByAddress(section_start[section_list[j]])
		pagesize=MemPage_addr.getSize()
		for i in range(0,pagesize):
			page_readMemory=imm.readMemory(section_start[section_list[j]]+i,1)
			section_str[section_list[j]] += page_readMemory.encode("hex")
	
	
	for j in range(0,list_count):
		imm.log("section : %s" % section_list[j])
		imm.log("section string : %s" % section_str[section_list[j][0:16]])
	
	
	root_place = "C:\\Users\\unpacking\\Desktop" + "\\" + filename[:-4]
	f=open(root_place,'wb')
	for i in range(0,list_count):
		data = section_str[section_list[i]]
		f.write(binascii.unhexlify(data))
	
	f.close()
	return 'sucess'
	
	
if __name__=="__main__":
	print "This module is for use within Immunity Debugger only"