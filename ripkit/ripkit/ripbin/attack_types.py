from enum import Enum

class CompileTimeAttacks(Enum):
    """
    Compile time attack names and there flags
    """

    #fpath4 = "-C -fpatchable-function-entry=4" # clang option that isn't supported by rustc

    # Codegen Options

    frame_pointers = "-C force-frame-pointers"
    inline_threshold = "-C inline-threshold=0" # No Inline (higher threshold means more inlining)
    no_redzone = "-C no-redzone"
    pic_reloc_model = "-C relocation-model=pic" # Position Independent Code
    pie_reloc_model = "-C relocation-model=pie" # Position Independent Executable
    ropi_rwpi_reloc_model = "-C relocation-model=ropi-rwpi" # Combined Read-Only and Read-Write Position Independence

    # LLVM Options

    disable_tail_calls = "-C llvm-args=--disable-tail-calls"
    frame_pointer_none = "-C llvm-args=--frame-pointer=none" # codegen option above takes care of all frame-pointer option
    function_sections = "-C llvm-args=--function-sections"
    stackrealign = "-C llvm-args=--stackrealign"
    tailcallopt = "-C llvm-args=--tailcallopt"
    x86_align_branch = "-C llvm-args=--x86-align-branch=jcc+fused+jmp+call+ret+indirect" # Includes all available branch options
    x86_pad_max_prefix_size_0 = "-C llvm-args=--x86-pad-max-prefix-size=0" # No padding
    x86_pad_max_prefix_size_8 = "-C llvm-args=--x86-pad-max-prefix-size=8" # Some padding (most likely close to default)
    x86_pad_max_prefix_size_16 = "-C llvm-args=--x86-pad-max-prefix-size=16" # Lots of padded (may allow more than default)