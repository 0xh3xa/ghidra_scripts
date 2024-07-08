from ghidra.program.model.symbol import RefType

def extract_function_calls():
    program = currentProgram
    listing = program.getListing()
    
    function_calls = {}
    
    # Iterate over all functions in the program
    function_iterator = listing.getFunctions(True)
    while function_iterator.hasNext():
        function = function_iterator.next()
        function_name = function.getName()
        function_calls[function_name] = []

        # Iterate over all instructions in the function
        instructions = listing.getInstructions(function.getBody(), True)
        for instruction in instructions:
            if instruction.getFlowType().isCall():
                # Get the called function
                references = instruction.getReferencesFrom()
                for reference in references:
                    if reference.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                        called_function = getFunctionAt(reference.getToAddress())
                        if called_function:
                            called_function_name = called_function.getName()
                            function_calls[function_name].append(called_function_name)

    return function_calls

def print_function_calls(function_calls):
    for caller, callees in function_calls.items():
        for callee in callees:
            print(caller + '->' + callee)

def main():
    function_calls = extract_function_calls()
    print_function_calls(function_calls)

main()
