from ghidra.program.model.symbol import SymbolType

def extract_imported_functions():
    program = currentProgram
    symbol_table = program.getSymbolTable()

    # Dictionary to store DLLs and their functions
    imported_functions = {}

    # Iterate over all external symbols
    external_symbols = symbol_table.getExternalSymbols()
    for symbol in external_symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            function_name = symbol.getName()
            library_name = symbol.getParentNamespace().getName()
            if library_name not in imported_functions:
                imported_functions[library_name] = []
            imported_functions[library_name].append(function_name)

    return imported_functions

def print_imported_functions(imported_functions):
    for dll, functions in imported_functions.items():
        print("Library: " + dll)
        for function in functions:
            print("  Function: " + function)

def main():
    imported_functions = extract_imported_functions()
    print_imported_functions(imported_functions)

main()
