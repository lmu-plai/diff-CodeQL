# DiffStaticAnalyzer - Differential Static Analysis Tool for npm Packages to Detect Malicious Updates

## Overview

DiffStaticAnalyzer is a command-line tool designed for detecting malicious code in npm packages. It provides functionality to scan packages, run evaluations, and obtain overall update frequency information.
For its detection it relies on the static code analysis tool CodeQL. 

A query set for the detection of suspicious behavior in JavaScript code is provided in the directory xy. 
The tool will compare the CodeQL results resp. findings of two versions to identify the new findings of the second version, relevant for the detection. 
The severity values of these differential findings will sumed up and compared to a predfined threshold, determining whether a certain update is flagged as potentially malicious.

## Prerequisites

Before using DiffStaticAnalyzer, ensure that [CodeQL](https://codeql.github.com/) is installed on your system.

1. **Download CodeQL CLI:**
   Visit the [CodeQL CLI download page](https://github.com/github/codeql-cli-binaries/releases) and download the appropriate version for your operating system.

2. **Extract the Archive:**
   Extract the downloaded archive to a location of your choice.

3. **Add CodeQL to PATH:**
   Add the CodeQL executable to your system's PATH to make it accessible from the command line.

   - On Linux/macOS, you can add the following line to your shell profile file (e.g., `~/.bashrc` or `~/.zshrc`):

     ```bash
     export PATH=/path/to/codeql:$PATH
     ```

   - On Windows, you can update the system's PATH environment variable to include the directory containing the `codeql` executable.

4. **Verify Installation:**
   Open a new terminal window and run the following command to verify that CodeQL is installed:

   ```bash
   codeql --version
   ```

   You should see the installed CodeQL version.

Now you're ready to use DiffStaticAnalyzer with the CodeQL CLI for npm package analysis.

## Installation

No installation is required. Simply clone this repository to your local machine.

```bash
git clone https://github.com/your-repo/diff-static-analyzer.git
```

## Usage

1. Copy the `.config.example` file, rename it to `.config` and enter all package names (from the official npm registry) and paths to packages you would like to scan. You can also enter further settings.
   <br>
   <br>
   Configuration Values:

   - `npm_package_names`: npm package names you would like to scan (e.g., `react`). Tool tries to download these packages from the npm registry.
   - `local_package_names`: Package names of local packages. These will not be attempted to be downloaded from the npm registry.
   - `path_to_queries`: Path to the CodeQL queries directory.
   - `list_of_additional_local_package_paths`: Path to directories with local package files (e.g. `malicious_packages,benign_packages`).
   - `result_format`: Specifies the CodeQL result format (e.g., sarif or csv). Full analysis with report only works with sarif for now.
   - `rescan`: Controls package rescanning during analysis. Applies CodeQL queries again and replaces previous results.
   - `severity_sum_threshold`: Sets the severity threshold for a package to be classified as potentially malicious. Recommended value: 10.
   - `custom_severity_policy`: Set custom severity values for CodeQl queries. Overwrites values in .ql query files for analysis.
   - `package_versions_to_skip`: Define specifiy package versions that should be skipped (e.g., because of processing errors).
   - `packages_to_sort_by_date`: Sorts these packages by version release date instead of semantic versioning.
   
   <br>

2. Run python command line tool with required flag:

   ```bash
   python diff_static_analyzer.py [--scan] [--evaluate] [--update-frequency]
   ```

3. The scanning results will be in the directory `packages` with each package generating its own folder. The file `result_PACKAGENAME.txt` represents the differential report and contains all scanning results including the flagged packages. The summary is at the end of the file.
4. Results for running the evaluation can be found in the directory `_evaluation`.

### Options

- `--scan`: Scan all packages defined in the config file.
- `--evaluate`: Run the evaluation of all scanned packages.
- `--update-frequency`: Get overall update frequency of packages.

## Example

```bash
python diff_static_analyzer.py --scan
```

This command will initiate the scanning process for the npm packages specified in the config file.

## Recreate paper/thesis evaluation data

1. Get malicious package versions from https://dasfreak.github.io/Backstabbers-Knife-Collection/ and https://github.com/osssanitizer/maloss. See `dataset.csv` and `dataset_version_names.txt` for details and exact package version names.
2. Create directory `malicious_packages` in this repository and put all malicious samples there as .tgz files.
3. (Optional) Create directory `benign_packages` in this repository and add local benign samples to it. Package versions not in npm anymore. See `dataset_version_names.txt`.
4. Check that `list_of_additional_local_package_paths` in the config file contains the path to the malicious samples and optional `benign_packages`.
5. Run the scan using `--scan` and after that run the evaluation using `--evaluate`.
6. The evaluation files will be stored in the directory `_evaluation`.