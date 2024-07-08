import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Pe2Assembly  extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get the current program
        Program program = getCurrentProgram();

        // Get the input file path
        String inputFilePath = program.getExecutablePath();
        if (inputFilePath == null) {
            println("Program has no file path.");
            return;
        }

        // Get the parent folder name of the input file
        String parentFolder = getParentFolderName(inputFilePath);
        if (parentFolder == null) {
            println("Failed to get parent folder name.");
            return;
        }

        // Create the output directory
        String outputDirPath = parentFolder + "-assembly";
        createDirectory(outputDirPath);

        String filePath = inputFilePath.toString();
        String fileName = filePath.substring(filePath.lastIndexOf("/") + 1).replace(".exe", "");

        // Extract assembly instructions
        extractAssembly(program, outputDirPath, fileName);

        // Extract functions and symbols
        extractFunctionsAndSymbols(program, outputDirPath, fileName);

        println("Analysis completed.");
    }

    private void extractAssembly(Program program, String outputDirPath, String fName) {
        try {
            String fileName = outputDirPath + File.separator + fName + ".asm";
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
            Listing listing = program.getListing();
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock block : blocks) {
                AddressSetView blockRange = new AddressSet(block.getStart(), block.getEnd());
                if (block.isExecute()) {
                    InstructionIterator instructions = listing.getInstructions(blockRange, true);
                    while (instructions.hasNext() && !monitor.isCancelled()) {
                        Instruction instruction = instructions.next();
                        writer.println(instruction.toString());
                    }
                }
            }
            writer.close();
            println("Assembly instructions saved to: " + fileName);
        } catch (IOException e) {
            println("Error writing assembly file: " + e.getMessage());
        }
    }

    private void extractFunctionsAndSymbols(Program program, String outputDirPath, String fName) {
        try {
            String fileName = outputDirPath + File.separator + fName + "-functions_and_symbols.txt";
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
            SymbolTable symbolTable = program.getSymbolTable();
            for (Symbol symbol : symbolTable.getAllSymbols(true)) {
                writer.println(symbol.getName() + " : " + symbol.getAddress());
            }
            FunctionManager functionManager = program.getFunctionManager();
            for (Function function : functionManager.getFunctions(true)) {
                writer.println(function.getEntryPoint() + " : " + function.getName());
            }
            writer.close();
            println("Functions and symbols saved to: " + fileName);
        } catch (IOException e) {
            println("Error writing functions and symbols file: " + e.getMessage());
        }
    }

    private String getParentFolderName(String filePath) {
        Path parentPath = Paths.get(filePath).getParent();
        if (parentPath != null) {
            return parentPath.toString();
        }
        return null;
    }

    private void createDirectory(String dirPath) {
        try {
            Path path = Paths.get(dirPath);
            Files.createDirectories(path);
        } catch (IOException e) {
            println("Error creating directory: " + e.getMessage());
        }
    }
}
