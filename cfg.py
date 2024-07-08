from ghidra.program.model.symbol import RefType
import os

def extract_function_calls():
    program = currentProgram
    listing = program.getListing()
    
    function_calls = {}
    
    function_iterator = listing.getFunctions(True)
    while function_iterator.hasNext():
        function = function_iterator.next()
        function_name = function.getName()
        function_calls[function_name] = []

        instructions = listing.getInstructions(function.getBody(), True)
        for instruction in instructions:
            if instruction.getFlowType().isCall():
                references = instruction.getReferencesFrom()
                for reference in references:
                    if reference.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                        called_function = getFunctionAt(reference.getToAddress())
                        if called_function:
                            called_function_name = called_function.getName()
                            function_calls[function_name].append(called_function_name)

    return function_calls

def write_function_calls_to_file(function_calls, filename):
    with open(filename, 'w') as file:
        for caller, callees in function_calls.items():
            for callee in callees:
                file.write(caller + '->' + callee + '\n')

def main():
    function_calls = extract_function_calls()

    program_path = currentProgram.getExecutablePath()
    base_name = os.path.basename(os.path.splitext(program_path)[0])
    dir_name = os.path.dirname(program_path)
    
    output_dir = os.path.join(dir_name, 'control-flow-graph')

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_filename = os.path.join(output_dir, base_name + '.cfg')

    write_function_calls_to_file(function_calls, output_filename)
    print("Function calls written to {}".format(output_filename))

main()
