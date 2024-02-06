import idc
import idaapi 
import idautils
import ida_ida
import ida_funcs

res = idaapi.auto_wait()
print(f"Auto wait res {res}")

print("FUNCTIONS:")
count = 0
#idc.AnalyzeArea(idc.SegStart(idc.ScreenEA()), idc.SegEnd(idc.ScreenEQ()))
#for ea in idautils.Functions():
start = ida_ida.inf_get_min_ea()
end = ida_ida.inf_get_max_ea()


#if start is None: start = ida_ida.inf_get_min_ea()
#if end is None:   end = ida_ida.inf_get_max_ea()
#
## find first function head chunk in the range
#chunk = ida_funcs.get_fchunk(start)
#if not chunk:
#    chunk = ida_funcs.get_next_fchunk(start)
#while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
#    chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
#func = chunk
#
#while func and func.start_ea < end:
#    startea = func.start_ea
#    endea = func.end_ea
#    yield startea, endea)
#    print(f"FUNCTION, {hex(startea)}, {hex(endea)}")
#    func = ida_funcs.get_next_func(startea)



#for (start_ea, end_ea) in idautils.Chunks(start,end):
#for (start_ea, end_ea) in idautils.Chunks(start):
print("FUNCTION_START_IND_RIPKIT")

for start_ea in idautils.Functions():
    count+=1
    #print("{}, {}".format(ea, idc.get_func_name(ea)))
    print(f"RIPKIT_FUNCTION<RIP_SEP>{start_ea}<RIP_SEP>{ida_funcs.calc_func_size(start_ea)}<RIP_SEP>{idc.get_func_name(start_ea)}")
print("FUNCTIONS count :" + str(count))

print("FUNCTION_END_IND_RIPKIT")
qexit(0)
