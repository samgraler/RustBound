

import idc
import idaapi 
import idautils

#print("Hello")

# Could log to an external log file 

res = idaapi.auto_wait()
print(f"Auto wait res {res}")

print("FUNCTIONS:")
count = 0
#idc.AnalyzeArea(idc.SegStart(idc.ScreenEA()), idc.SegEnd(idc.ScreenEQ()))
for ea in idautils.Functions():
    count+=1
    #print("{}, {}".format(ea, idc.get_func_name(ea)))
    print(f"FUNCTION, {hex(ea)}, {idc.get_func_name(ea)}")
print("FUNCTIONS count :" + str(count))

qexit(0)
