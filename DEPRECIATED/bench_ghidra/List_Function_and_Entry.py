#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here


import ghidra.app.script.GhidraScript

import os 

from ghidra.util.task import ConsoleTaskMonitor

counter = 0

functions = currentProgram.getFunctionManager().getFunctions(True)
print(" ======================= BEGIN FUNCTION LIST (Name, Entry) =======================================")

# Define the path for the log file
#log_file_path = os.path.join(os.path.expanduser("~/ghidra_functions/"),
#                             os.path.basename(currentProgramExecutablePath())


# Open the log file for writing
#with open(log_file_path, "w") as log_file:
for function in functions:
   #println("Function Name: " + function.getName())
    print("FOUND_FUNC <BENCH_SEP> {} <BENCH_SEP> {}".format(function.getName(), function.getEntryPoint()))

    counter += 1
   # Write to the log file
   #log_file.write(out_str + "\n")


print(" ======================= END FUNCTION LIST (Name, Entry) =======================================")
print(counter)







