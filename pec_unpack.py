import immlib
import pefile
import math
import array
import os

def main(args):
	imm=immlib.Debugger()
	curAddr=imm.getRegs()['EIP']
	i=0
	imm.log("curAddr: 0x%08X" % curAddr)
	while i<100:
		op=imm.disasm(curAddr)
		opsize=op.getOpSize()
		if op.getResult()=="JMP EAX":
			imm.run(curAddr)
			imm.stepOver()
			return
		else:
			curAddr=curAddr+opsize
			i+=1