#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
import ghidra.app.script.GhidraScript
import os 
from ghidra.util.task import ConsoleTaskMonitor

counter = 0
functions = currentProgram.getFunctionManager().getFunctions(True)
print(" ======================= BEGIN FUNCTION LIST (Name, Entry) =======================================")
for function in functions:
   #println("Function Name: " + function.getName())
    size = function.getBody().getNumAddresses()
    print("FOUND_FUNC, {}, {}, {}".format(function.getName(), function.getEntryPoint(), size))
    counter += 1
# According to https://github.com/NationalSecurityAgency/ghidra/issues/835, the GUI is doing:
#   Size = FunctionObject.getBody().getNumAddresses()
# Specifially this is no method that simply returns the size of a function... this leads me to wonder if
# the size ends bounds of the functions do not matter as much for how ghidra is decompiling
print(" ======================= END FUNCTION LIST (Name, Entry) =======================================")
print(counter)
