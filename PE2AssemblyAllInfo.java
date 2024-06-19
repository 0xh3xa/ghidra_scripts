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
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.ExternalSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class PE2AssemblyAllInfo extends GhidraScript {
    
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
    
            String fileName = Paths.get(inputFilePath).getFileName().toString();
            String baseName = fileName.substring(0, fileName.lastIndexOf('.'));
    
            // Extract assembly instructions
            extractAssembly(program, outputDirPath, baseName);
    
            // Extract functions and symbols
            extractFunctionsAndSymbols(program, outputDirPath, baseName);
    
            // Extract imported functions from DLLs
            extractImportedFunctions(program, outputDirPath, baseName);
    
            println("Analysis completed.");
        }
    
        private void extractAssembly(Program program, String outputDirPath, String baseName) {
            try {
                String fileName = outputDirPath + File.separator + baseName + ".asm";
                PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
                Listing listing = program.getListing();
                for (Instruction instruction : listing.getInstructions(true)) {
                    writer.println(instruction.toString());
                }
                writer.close();
                println("Assembly instructions saved to: " + fileName);
            } catch (IOException e) {
                println("Error writing assembly file: " + e.getMessage());
            }
        }
    
        private void extractFunctionsAndSymbols(Program program, String outputDirPath, String baseName) {
            try {
                String fileName = outputDirPath + File.separator + baseName + "-functions_and_symbols.txt";
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
    
        private void extractImportedFunctions(Program program, String outputDirPath, String baseName) {
            try {
                String fileName = outputDirPath + File.separator + baseName + "-imported_functions.txt";
                PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
    
                ExternalManager externalManager = program.getExternalManager();
                ExternalSymbol[] externalSymbols = externalManager.getExternalSymbols();
                for (ExternalSymbol externalSymbol : externalSymbols) {
                    if (externalSymbol.getLibraryName().endsWith(".dll")) {
                        writer.println("DLL: " + externalSymbol.getLibraryName());
                        writer.println("Function: " + externalSymbol.getLabel());
                        writer.println("Address: " + externalSymbol.getAddress());
                        writer.println();
                    }
                }
    
                writer.close();
                println("Imported functions saved to: " + fileName);
            } catch (IOException e) {
                println("Error writing imported functions file: " + e.getMessage());
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
                if (!Files.exists(path)) {
                    Files.createDirectories(path);
                }
            } catch (IOException e) {
                println("Error creating directory: " + e.getMessage());
            }
        }
    }
}