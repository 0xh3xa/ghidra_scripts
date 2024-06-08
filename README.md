# Ghidra - Headless Scripts (Java)

Headless Scripts for Ghidra's Headless Analyzer written in Java for Automated Disassembly.

### Headless Analyzer

The headless analyzer is used to automate the process of analysis, decompiled, disassembly, etc. 

### Headless Analyzer Arguments

The arguments of the headless analyzer could be found in <a href="https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html">link</a>

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

### Examples

```
$ analyzeHeadless <PROJECT_PATH> <PROJECT_NAME> -import <FILE_TO_ANALYZE> -scriptPath <PATH_TO_YOUR_SCRIPTS_FOLDER> -postScript <SCRIPT_FILENAME>
```

You can find the analyzerheadless in the in Linux in `/opt/ghidra/support/analyzeHeadless`, usage

```
/opt/ghidra/support/analyzeHeadless ~/test-project disassemble -import /home/user/reverse/binaries -postScript ~/ghidra_scripts/PE_TO_ASSEMBLY.java 
```
