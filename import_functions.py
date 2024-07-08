from ghidra.program.model.symbol import SymbolType
import os

def extract_imported_functions():
    program = currentProgram
    symbol_table = program.getSymbolTable()

    imported_functions = {}

    external_symbols = symbol_table.getExternalSymbols()
    for symbol in external_symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            function_name = symbol.getName()
            library_name = symbol.getParentNamespace().getName()
            if library_name not in imported_functions:
                imported_functions[library_name] = []
            imported_functions[library_name].append(function_name)

    return imported_functions

def write_imported_functions_to_file(imported_functions, filename):
    with open(filename, 'w') as file:
        for dll, functions in imported_functions.items():
            file.write("Library: " + dll + '\n')
            for function in functions:
                file.write("  Function: " + function + '\n')

def main():
    imported_functions = extract_imported_functions()

    program_path = currentProgram.getExecutablePath()
    base_name = os.path.basename(os.path.splitext(program_path)[0])
    dir_name = os.path.dirname(program_path)
    
    output_dir = os.path.join(dir_name, 'imported-functions')

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_filename = os.path.join(output_dir, base_name + '.imports')

    write_imported_functions_to_file(imported_functions, output_filename)
    print("Imported functions written to {}".format(output_filename))

main()
