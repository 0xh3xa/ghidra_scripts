# Ghidra Analysis Scripts

![Ghidra-Reverse](https://img.shields.io/badge/Ghidra--Reverse-blue?style=flat&logo=github)
![Language](https://img.shields.io/badge/Language-Java-orange)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-purple)
![Status](https://img.shields.io/badge/Status-Active-success)

A collection of **Ghidra Java & Python scripts** focused on **automated disassembly and analysis**, designed to work with **Ghidra Headless Analyzer**.

This repository is intended for:
- Malware analysis
- Automated reverse engineering
- Batch disassembly
- Research and experimentation
- Headless Ghidra workflows

## 📌 Features
- ✅ Java & Python based Ghidra scripts
- ✅ Headless analyzer support
- ✅ Automated disassembly & analysis
- ✅ Suitable for malware research
- ✅ Scalable for batch processing  

## Use Cases
- Malware analysis automation
- Static binary analysis
- Reverse engineering research


## 🧩 Headless Analyzer

The **Ghidra Headless Analyzer** allows you to run Ghidra without the GUI and automate analysis tasks such as:

- Importing binaries
- Disassembly & decompilation
- Running scripts
- Batch analysis

## ⚙️ Headless Analyzer Arguments

Documentation:  
🔗 https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html

```bash
analyzeHeadless <project_location> <project_name>[/<folder_path>] | ghidra://<server>[:<port>]/<repository_name>[/<folder_path>]
    [[-import [<directory>|<file>]+] | [-process [<project_file>]]]
    [-preScript <ScriptName> [<arg>]*]
    [-postScript <ScriptName> [<arg>]*]
    [-scriptPath "<path1>[;<path2>...]"]
    [-propertiesPath "<path1>[;<path2>...]"]
    [-scriptlog <path to script log file>]
    [-log <path to log file>]
    [-overwrite]
    [-recursive]
    [-readOnly]
    [-deleteProject]
    [-noanalysis]
    [-processor <languageID>]
    [-cspec <compilerSpecID>]
    [-analysisTimeoutPerFile <timeout in seconds>]
    [-keystore <KeystorePath>]
    [-connect [<userID>]]
    [-p]
    [-commit ["<comment>"]]
    [-okToDelete]
    [-max-cpu <max cpu cores to use>]
    [-loader <desired loader name>]
```

## Usage Example

### Basic Usage

```bash
analyzeHeadless <PROJECT_PATH> <PROJECT_NAME> \
  -import <FILE_TO_ANALYZE> \
  -scriptPath <PATH_TO_SCRIPTS> \
  -postScript <SCRIPT_NAME>
```

Linux Example, the headless analyzer is typically located at: `/opt/ghidra/support/analyzeHeadless`

```bash
/opt/ghidra/support/analyzeHeadless \
  ~/test-project disassemble \
  -import /home/user/reverse/binaries \
  -postScript ~/ghidra_scripts/PE_TO_ASSEMBLY.java
```
