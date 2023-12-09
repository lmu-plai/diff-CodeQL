import os
import re
import csv
import json
import time
import shutil
import logging
import datetime
import argparse

import numpy as np
import pandas as pd
import seaborn as sns
import scipy.stats as stats
import requests
import subprocess
import configparser

from matplotlib import pyplot as plt
from natsort import natsorted
from scipy.stats import linregress
from sklearn import metrics
from bs4 import BeautifulSoup


class NPMPackage:

    def __init__(self, name, local=False):
        self.name = name
        self.local = local
        self.type = "Benign"
        self.malicious_versions = []
        self.stats_file = ""


class CheckNPMPackage:

    def __init__(self, package_names, loc_package_names, queries_path, additional_local_packages=None,
                 result_format="sarif", threshold: float = None, rescan=False, policy=None,
                 package_versions_to_skip=None, packages_to_sort_by_date=None):

        self.package = None
        self.packages = []
        self.queries_path = queries_path
        self.additional_local_packages = additional_local_packages
        self.result_format = result_format
        self.rescan = rescan
        self.threshold = threshold
        self.policy = policy
        self.package_versions_to_skip = package_versions_to_skip
        self.packages_to_sort_by_date = packages_to_sort_by_date

        # Process NPM package names
        if package_names:
            if isinstance(package_names, list):
                for package_name in package_names:
                    self.packages.append(NPMPackage(name=package_name, local=False))
            else:
                self.packages.append(NPMPackage(name=package_names, local=False))

        if loc_package_names:
            # Process local package names
            if isinstance(loc_package_names, list):
                for package_name in local_package_names:
                    self.packages.append(NPMPackage(name=package_name, local=True))
            else:
                self.packages.append(NPMPackage(name=loc_package_names, local=True))

    def run_pipeline(self):

        print(f"Starting pipeline...")

        # Run scanning pipeline for all packages
        for package in self.packages:
            
            self.package = package
            self.package.stats_file = os.path.join("packages", package.name, f"{package.name}_stats.json")

            print(f"Processing NPM package {package.name}.")
            
            dir_package_path = os.path.join("packages", package.name)

            # Create main package dir
            if not os.path.exists(dir_package_path):
                os.mkdir(dir_package_path)

            log_file_path = os.path.join("packages", package.name, f"{package.name}.log")

            # Set up log file
            logging.basicConfig(filename=log_file_path, level=logging.INFO, filemode='a',
                                format='%(asctime)s %(levelname)s: %(message)s', force=True)

            # Step 1
            print("Step 1: Downloading package information file...")
            if not package.local:
                self.download_package_information()
        
            # Step 2
            print("Step 2: Downloading all package versions...")
            self.download_all_package_versions()

            # Step 3
            print("Step 3: Unpacking all package versions...")
            self.unpack_all_package_versions()
        
            # Step 4
            print("Step 4: Create CodeQL databases for all package versions...")
            self.create_code_ql_databases()
        
            # Step 5
            print("Step 5: Applying CodeQL queries to all package versions...")
            self.apply_queries_to_databases()
        
            # Step 6
            print("Step 6: Comparing result files of CodeQL queries...")
            if self.result_format == "sarif":
                flagged_versions, _ = self.compare_sarif_result_files()

                print()
                print("The following version have been flagged as potentially malicious:")

                for name, score in flagged_versions:
                    print(f"{name} with score {score}")

    # SCANNING PIPELINE
    # ------------------------

    def download_package_information(self):

        base_url = "https://registry.npmjs.org/"

        # Get the package info file
        data = requests.get(base_url + self.package.name)

        if data.status_code == 200:

            dir_package_path = os.path.join("packages", self.package.name)

            # Save package info file as json
            with open(os.path.join(dir_package_path, self.package.name + ".json"), 'wb') as file:
                file.write(data.content)
        else:
            logging.error("Package name not found in NPM registry. Check the spelling.")
            print("Error: Package name not found in NPM registry. Check the spelling.")
            exit()

    def download_all_package_versions(self):

        info_file_path = os.path.join("packages", self.package.name, self.package.name + ".json")

        dir_package_tgz = os.path.join("packages", self.package.name, "tgz")

        # Create database dir
        if not os.path.exists(dir_package_tgz):
            os.mkdir(dir_package_tgz)

        download_start_time = time.perf_counter()

        # Stats logging
        num_downloaded_packages = 0
        num_failed_packages = 0
        num_existing_packages = 0

        # Check if local package only
        if not self.package.local:

            # Parse info file
            with open(info_file_path, encoding="utf8") as f:
                json_data = json.load(f)

                # Get all tarball urls for all versions
                for k, v in json_data['versions'].items():

                    # New file path
                    target_path = os.path.join(dir_package_tgz, f"{v['name']}-{v['version']}.tgz")

                    # Check if file already exists
                    if not os.path.isfile(target_path):

                        # Download file
                        response = requests.get(v['dist']['tarball'], stream=True)

                        if response.status_code == 200:
                            with open(target_path, 'wb') as tgz_file:
                                tgz_file.write(response.raw.read())

                            num_downloaded_packages += 1
                        else:
                            logging.error(f"Downloading {v['name']}-{v['version']}.tgz from "
                                          f"{v['dist']['tarball']} failed. "
                                          f"Reponse code: {response.status_code}, Content: {response.content}")
                            num_failed_packages += 1

                    else:
                        # File already exists
                        num_existing_packages += 1

        download_stop_time = time.perf_counter()

        logging.info(f"Downloaded {num_downloaded_packages} package(s) in "
                     f"{download_stop_time - download_start_time:0.4f} seconds")

        self.write_package_stats_file('package_dowloading', num_downloaded_packages,
                                      download_stop_time - download_start_time)

        if num_failed_packages > 0:
            logging.info(f"Download of {num_failed_packages} package(s) failed.")
            print(f"WARNING: Download of {num_failed_packages} package(s) failed. Please see log file for details.")

        if num_existing_packages > 0:
            logging.info(f"Skipped {num_existing_packages} package(s) because they already exist.")

        # Check for additional local package versions and copy it to tgz dir
        if self.additional_local_packages:
            for packages_path in self.additional_local_packages:
                # Check all files if it is version of current page
                for file in os.listdir(packages_path):
                    # Check if the package name is equal to the package name of the file
                    if self.package.name == re.match(r'^(.+?)-\d+\.\d+\.\d+(-\w+)?\.tgz$', file).group(1):
                        # Try to copy package if not existing already
                        if not os.path.isfile(os.path.join(dir_package_tgz, file)):
                            shutil.copy(os.path.join(packages_path, file), os.path.join(dir_package_tgz, file))
                            logging.info(f"Additional local package '{file}' has been copied successfully.")
                        else:
                            logging.info("Additional local package is already existing at target.")

                        if 'malicious_packages' in packages_path:
                            self.package.type = "Malicious"
                            self.package.malicious_versions.append(os.path.splitext(file)[0])

    def unpack_all_package_versions(self):

        dir_package_path = os.path.join("packages", self.package.name, "tgz")

        dir_package_unpacked = os.path.join("packages", self.package.name, "unpacked")

        # Create database dir
        if not os.path.exists(dir_package_unpacked):
            os.mkdir(dir_package_unpacked)

        # Stats logging
        num_unpacked_packages = 0
        num_existing_packages = 0

        unpacking_start_time = time.perf_counter()

        # Loop through all files
        for file in os.listdir(dir_package_path):

            if file.endswith(".tgz"):

                file_path = os.path.join(dir_package_path, file)
                output_path = os.path.join(dir_package_unpacked, os.path.splitext(file)[0])

                # Check if output directory / unpacked package already exists
                if not os.path.exists(output_path):

                    try:
                        temp_unpacked_path = os.path.join(dir_package_path, os.path.splitext(file)[0])

                        # Unpack tgz
                        subprocess.run(["7z", "e", file_path, "-y", f"-o{temp_unpacked_path}"], check=True)

                        temp_tar_file_path = os.path.join(temp_unpacked_path, f"{os.path.splitext(file)[0]}.tar")

                        # Unpack tar to final location
                        subprocess.run(["7z", "x", temp_tar_file_path, "-y", f"-o{output_path}"], check=True)

                        # Delete temp dir
                        shutil.rmtree(temp_unpacked_path)

                        num_unpacked_packages += 1

                    except subprocess.SubprocessError as e:
                        logging.error(f"Unpacking for file \"{file}\" failed: {e}")
                        print(f"Unpacking for file \"{file}\" failed: {e}")
                        continue

                else:
                    # Dir already exists
                    num_existing_packages += 1

        unpacking_stop_time = time.perf_counter()

        logging.info(f"Unpacked {num_unpacked_packages} package(s) in "
                     f"{unpacking_stop_time - unpacking_start_time:0.4f} seconds")

        self.write_package_stats_file('package_unpacking', num_unpacked_packages,
                                      unpacking_stop_time - unpacking_start_time)

        if num_existing_packages > 0:
            logging.info(f"Skipped {num_existing_packages} package(s) because they already exist.")

    def create_code_ql_databases(self):

        dir_package_path = os.path.join("packages", self.package.name, "unpacked")
        dir_package_databases = os.path.join("packages", self.package.name, "databases")

        # Create database dir
        if not os.path.exists(dir_package_databases):
            os.mkdir(dir_package_databases)

        # Stats logging
        num_created_databases = 0
        num_existing_databases = 0

        creating_databases_start_time = time.perf_counter()

        num_files = len(os.listdir(dir_package_path))

        # Loop through all files
        for idx, file in enumerate(os.listdir(dir_package_path)):

            print(f"Creating database for {self.package.name}: {idx+1}/{num_files}")

            unpacked_package_path = os.path.join(dir_package_path, file)
            ql_database_path = os.path.join(dir_package_databases, f"{file}_ql-db")

            # Check if database already exists
            if not os.path.exists(ql_database_path):

                try:
                    subprocess.run(["codeql", "database", "create", "--language=javascript", "--source-root",
                                    unpacked_package_path, "--threads=0", ql_database_path], check=True)

                    num_created_databases += 1

                except subprocess.SubprocessError as e:
                    logging.info(f"Could not create database for file \"{file}\": {e}")
                    print(f"Could not create database for file \"{file}\": {e}")

                    creating_databases_stop_time = time.perf_counter()

                    logging.info(f"Created database(s) for {num_created_databases} package(s) in "
                                 f"{creating_databases_stop_time - creating_databases_start_time:0.4f} seconds")

                    self.write_package_stats_file("database_generation", num_created_databases,
                                                  creating_databases_stop_time - creating_databases_start_time)
                    return

            else:
                # Database already exits
                num_existing_databases += 1

        creating_databases_stop_time = time.perf_counter()

        logging.info(f"Created database(s) for {num_created_databases} package(s) in "
                     f"{creating_databases_stop_time - creating_databases_start_time:0.4f} seconds")

        self.write_package_stats_file("database_generation", num_created_databases,
                                      creating_databases_stop_time - creating_databases_start_time)

        if num_existing_databases > 0:
            logging.info(f"Skipped {num_existing_databases} package(s) because database(s) already exist.")

    def apply_queries_to_databases(self):

        if self.result_format == "sarif":
            format_argument = "--format=sarifv2.1.0"
        elif self.result_format == "csv":
            format_argument = "--format=csv"
        else:
            raise Exception("Unknown result format.")

        dir_package_databases = os.path.join("packages", self.package.name, "databases")
        dir_package_code_ql_results = os.path.join("packages", self.package.name,
                                                   f"codeql_results_{self.result_format}")

        if self.rescan:
            rerun = "--rerun"
        else:
            rerun = "--no-rerun"

        # Create CodeQL results dir
        if not os.path.exists(dir_package_code_ql_results):
            os.mkdir(dir_package_code_ql_results)

        # Stats logging
        num_applied_queries = 0
        num_existing_result_files = 0

        applying_queries_start_time = time.perf_counter()

        num_files = len(os.listdir(dir_package_databases))

        # Loop through all databases
        for idx, file in enumerate(os.listdir(dir_package_databases)):

            print(f"Applying queries for {self.package.name}: {idx+1}/{num_files}")

            package_database_path = os.path.join(dir_package_databases, file)
            result_file_path = os.path.join(dir_package_code_ql_results, f"{file}.{self.result_format}")

            # Check if result file already exists
            if not os.path.isfile(result_file_path) or self.rescan:

                try:
                    subprocess.run(["codeql", "database", "analyze", package_database_path, format_argument,
                                    f"--output={result_file_path}", "--threads=0", rerun, self.queries_path],
                                   check=True)

                    num_applied_queries += 1

                except subprocess.SubprocessError as e:
                    logging.info(f"Could not run CodeQL queries for \"{file}\": {e}")
                    print(f"Could not run CodeQL queries for \"{file}\": {e}")

                    # Check if we are allowed to skip this packages (version)
                    if file.replace("_ql-db", "") not in self.package_versions_to_skip:

                        applying_queries_stop_time = time.perf_counter()

                        logging.info(f"Applied queries for {num_applied_queries} package(s) in "
                                     f"{applying_queries_stop_time - applying_queries_start_time:0.4f} seconds")

                        self.write_package_stats_file('query_application', num_applied_queries,
                                                      applying_queries_stop_time -
                                                      applying_queries_start_time)

                        exit()
                    else:
                        logging.warning(f"The file: {file} will be skipped, because the queries could not be executed."
                                        f"Package version present in packages allowed to skip list.")

            else:
                # Result file already exists
                num_existing_result_files += 1

        applying_queries_stop_time = time.perf_counter()

        logging.info(f"Applied queries for {num_applied_queries} package(s) in "
                     f"{applying_queries_stop_time - applying_queries_start_time:0.4f} seconds")

        self.write_package_stats_file('query_application', num_applied_queries, applying_queries_stop_time -
                                      applying_queries_start_time)

        if num_existing_result_files > 0:
            logging.info(f"Skipped {num_existing_result_files} package(s) because result file(s) already exist.")

    def compare_sarif_result_files(self):
        """
            Compares the sarif results files resp. findings of CodeQL and
            creates differential report for each package.
        """

        dir_package = os.path.join("packages", self.package.name)

        # Result files path
        dir_package_code_ql_results = os.path.join(dir_package, "codeql_results_sarif")

        # Comparison file path
        dir_comparison_file_path = os.path.join(dir_package, f"result_{self.package.name}.txt")

        list_result_files_tmp = []

        # Create list of all result files
        for file in os.listdir(dir_package_code_ql_results):
            list_result_files_tmp.append(file)

        # Sort the list of files
        list_result_files = []

        # Check if sort by date or naturally by semantic versioning
        if self.packages_to_sort_by_date and self.package.name in self.packages_to_sort_by_date:

            # Special case to sort by date instead of version -> some packages have different release processes

            info_file_path = os.path.join("packages", self.package.name, self.package.name + ".json")

            # Parse info file
            with open(info_file_path, encoding="utf8") as f:
                json_data = json.load(f)

                # Get times
                times = json_data['time']
                versions_by_time = []

                for a_time in times.items():
                    if a_time[0] == "created" or a_time[0] == "modified":
                        pass
                    else:
                        versions_by_time.append((f"{self.package.name}-{a_time[0]}_ql-db.sarif", a_time[1]))

                # Convert strings to datetime objects
                date_format = "%Y-%m-%dT%H:%M:%S.%fZ"

                # Sort the datetime objects
                versions_sorted = sorted(versions_by_time, key=lambda x: datetime.datetime.strptime(x[1], date_format))

            for file_name, _ in versions_sorted:
                if file_name in list_result_files_tmp:
                    list_result_files.append(file_name)
        else:
            # Sort by version
            list_result_files = natsorted(list_result_files_tmp)

        # Version flagged as malicious and benign ones
        flagged_versions = []
        benign_versions = []

        severities = {}

        # Load policy if set
        if self.policy:
            with open(self.policy, encoding="utf-8") as f:
                severities = json.load(f)

        # Write comparison to file
        with open(dir_comparison_file_path, 'w', encoding="utf-8") as result_file:

            # Compare each two files in a row
            for idx, file in enumerate(list_result_files):

                if len(list_result_files) > idx + 1:

                    # Get names of the package versions (remove "_ql-db.sarif")
                    name_version_1 = file[:len(file) - 12]
                    name_version_2 = list_result_files[idx + 1][:len(list_result_files[idx + 1]) - 12]

                    result_file.write(f"Comparing {name_version_1} to {name_version_2}:\n")
                    result_file.write(f"---------------------------------------------------------\n\n")

                    results_of_report_1 = {}
                    results_of_report_2 = {}

                    severity_sum = 0
                    severity_sum_distinct_queries = 0
                    query_ids = []

                    # Parse sarif report 1
                    with open(os.path.join(dir_package_code_ql_results, file), encoding="utf-8") as f:
                        json_data = json.load(f)

                        if not self.policy:
                            # Get severities for queries
                            for rule in json_data['runs'][0]['tool']['driver']['rules']:
                                if 'security-severity' in rule['properties']:
                                    severities[rule['id']] = float(rule['properties']['security-severity'])

                        for result in json_data['runs'][0]['results']:

                            query_id = result['ruleId']
                            message = result['message']['text']
                            source_file = result['locations'][0]['physicalLocation']['artifactLocation']['uri']

                            # Get location
                            if 'region' in result['locations'][0]['physicalLocation']:

                                location = str(result['locations'][0]['physicalLocation']['region']['startLine'])

                                if 'startColumn' in result['locations'][0]['physicalLocation']['region']:

                                    location += ":" + str(result['locations'][0]['physicalLocation']['region'][
                                        'startColumn'])
                                else:
                                    location += ":N/A"
                            else:
                                location = "N/A"

                            if query_id not in results_of_report_1:
                                results_of_report_1[query_id] = {}
                                results_of_report_1[query_id]['count'] = 1
                                results_of_report_1[query_id]['messages'] = {}

                            else:
                                results_of_report_1[query_id]['count'] += 1

                            if message not in results_of_report_1[query_id]['messages']:
                                results_of_report_1[query_id]['messages'][message] = {}
                                results_of_report_1[query_id]['messages'][message]['count'] = 1
                                results_of_report_1[query_id]['messages'][message]['files'] = {}

                                results_of_report_1[query_id]['messages'][message]['files'][source_file] = {}
                                results_of_report_1[query_id]['messages'][message]['files'][source_file]['count'] = 1
                                results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                    'locations'] = {}
                                results_of_report_1[query_id]['messages'][message]['files'][source_file]['locations'][
                                    location] = 1
                            else:
                                results_of_report_1[query_id]['messages'][message]['count'] += 1

                                if source_file not in results_of_report_1[query_id]['messages'][message]['files']:

                                    results_of_report_1[query_id]['messages'][message]['files'][source_file] = {}
                                    results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                        'count'] = 1
                                    results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                        'locations'] = {}

                                    results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                        'locations'][
                                        location] = 1
                                else:

                                    results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                        'count'] += 1

                                    if location not in \
                                            results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                                'locations']:
                                        results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                            'locations'][location] = 1
                                    else:
                                        results_of_report_1[query_id]['messages'][message]['files'][source_file][
                                            'locations'][location] += 1

                    # Parse sarif report 2
                    with open(os.path.join(dir_package_code_ql_results, list_result_files[idx + 1]),
                              encoding="utf-8") as f:
                        json_data = json.load(f)

                        for result in json_data['runs'][0]['results']:

                            query_id = result['ruleId']
                            message = result['message']['text']
                            source_file = result['locations'][0]['physicalLocation']['artifactLocation']['uri']

                            # Get location
                            if 'region' in result['locations'][0]['physicalLocation']:

                                location = str(result['locations'][0]['physicalLocation']['region']['startLine'])

                                if 'startColumn' in result['locations'][0]['physicalLocation']['region']:

                                    location += ":" + str(result['locations'][0]['physicalLocation']['region'][
                                        'startColumn'])
                                else:
                                    location += ":N/A"
                            else:
                                location = "N/A"

                            if query_id not in results_of_report_2:
                                results_of_report_2[query_id] = {}
                                results_of_report_2[query_id]['count'] = 1
                                results_of_report_2[query_id]['messages'] = {}

                            else:
                                results_of_report_2[query_id]['count'] += 1

                            if message not in results_of_report_2[query_id]['messages']:
                                results_of_report_2[query_id]['messages'][message] = {}
                                results_of_report_2[query_id]['messages'][message]['count'] = 1
                                results_of_report_2[query_id]['messages'][message]['files'] = {}

                                results_of_report_2[query_id]['messages'][message]['files'][source_file] = {}
                                results_of_report_2[query_id]['messages'][message]['files'][source_file]['count'] = 1
                                results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                    'locations'] = {}
                                results_of_report_2[query_id]['messages'][message]['files'][source_file]['locations'][
                                    location] = 1
                            else:
                                results_of_report_2[query_id]['messages'][message]['count'] += 1

                                if source_file not in results_of_report_2[query_id]['messages'][message]['files']:

                                    results_of_report_2[query_id]['messages'][message]['files'][source_file] = {}
                                    results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                        'count'] = 1
                                    results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                        'locations'] = {}

                                    results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                        'locations'][location] = 1
                                else:

                                    results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                        'count'] += 1

                                    if location not in \
                                            results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                                'locations']:
                                        results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                            'locations'][location] = 1
                                    else:
                                        results_of_report_2[query_id]['messages'][message]['files'][source_file][
                                            'locations'][location] += 1

                    # Compare results
                    for query_id, query_data in results_of_report_2.items():

                        query_report_text = ""

                        if query_id in results_of_report_1.keys():

                            for message, message_data in query_data['messages'].items():

                                message_count_2 = results_of_report_2[query_id]['messages'][message]['count']

                                if message in results_of_report_1[query_id]['messages'].keys():

                                    message_count_1 = results_of_report_1[query_id]['messages'][message]['count']

                                    if message_count_2 > message_count_1:

                                        message_diff = results_of_report_2[query_id]['messages'][message]['count'] - \
                                                       results_of_report_1[query_id]['messages'][message]['count']

                                        query_report_text += f"\t{message_diff} new occurence(s) of finding: " \
                                                             f"{message}\n"

                                        files_1 = results_of_report_1[query_id]['messages'][message]['files']
                                        files_2 = results_of_report_2[query_id]['messages'][message]['files']

                                        query_report_text += f"\t\tFile(s):\n"

                                        # Check if we can detect new files (with the finding)
                                        for source_file in files_2:
                                            if source_file not in files_1:
                                                query_report_text += f"\t\t\t{source_file}\n"

                                                query_report_text += f"\t\t\t\tLocation(s):\n"

                                                # Write all locations in file
                                                for location in \
                                                        results_of_report_2[query_id]['messages'][message]['files'][
                                                            source_file]['locations']:
                                                    query_report_text += f"\t\t\t\t\t{location}\n"

                                            else:
                                                if results_of_report_2[query_id]['messages'][message]['files'][
                                                    source_file]['count'] > \
                                                        results_of_report_1[query_id]['messages'][message]['files'][
                                                            source_file]['count']:
                                                    query_report_text += f"\t\t\t{source_file}\n"

                                        # Evaluation of severity
                                        if query_id in severities:
                                            severity_sum += severities[query_id] * message_diff

                                            # Only count if new query (id)
                                            if query_id not in query_ids:
                                                query_ids.append(query_id)
                                                severity_sum_distinct_queries += severities[query_id]

                                else:
                                    query_report_text += f"\t{message_count_2} new occurence(s) of finding: {message}\n"

                                    query_report_text += f"\t\tFile(s):\n"

                                    # Write all files
                                    for source_file in results_of_report_2[query_id]['messages'][message]['files']:
                                        query_report_text += f"\t\t\t{source_file}\n"

                                        query_report_text += f"\t\t\t\tLocation(s):\n"

                                        # Write all locations in file
                                        for location in \
                                                results_of_report_2[query_id]['messages'][message]['files'][
                                                    source_file]['locations']:
                                            query_report_text += f"\t\t\t\t\t{location}\n"

                                    # Evaluation of severity
                                    if query_id in severities:
                                        severity_sum += severities[query_id] * message_count_2

                                        # Only count if new query (id)
                                        if query_id not in query_ids:
                                            query_ids.append(query_id)
                                            severity_sum_distinct_queries += severities[query_id]

                        else:

                            for message, message_data in query_data['messages'].items():

                                message_count_2 = results_of_report_2[query_id]['messages'][message]['count']

                                query_report_text += f"\t{message_count_2} new occurence(s) of finding: {message}\n"

                                query_report_text += f"\t\tFile(s):\n"

                                # Write all files
                                for source_file in results_of_report_2[query_id]['messages'][message]['files']:
                                    query_report_text += f"\t\t\t{source_file}\n"

                                    query_report_text += f"\t\t\t\tLocation(s):\n"

                                    # Write all locations in file
                                    for location in \
                                            results_of_report_2[query_id]['messages'][message]['files'][
                                                source_file]['locations']:
                                        query_report_text += f"\t\t\t\t\t{location}\n"

                                # Evaluation of severity
                                if query_id in severities:
                                    severity_sum += severities[query_id] * message_count_2

                                    # Only count if new query (id)
                                    if query_id not in query_ids:
                                        query_ids.append(query_id)
                                        severity_sum_distinct_queries += severities[query_id]

                        # Write results for query id to report file
                        if query_report_text != "":

                            if query_id in severities:
                                severity = f"severity: {severities[query_id]}"
                            else:
                                severity = "severity: N/A"

                            result_file.write(f"{query_id} ({severity}):\n")
                            result_file.write(f"{query_report_text}\n")

                    result_file.write(f"\nSeverity sum:\n=> All queries: {severity_sum}\n=> Distinct queries: "
                                      f"{severity_sum_distinct_queries}\n")

                    if self.threshold and severity_sum_distinct_queries >= self.threshold:
                        flagged_versions.append((name_version_2, severity_sum_distinct_queries))
                        result_file.write("Flagged as potential malicious.\n")
                    else:
                        benign_versions.append((name_version_2, severity_sum_distinct_queries))

                    result_file.write(f"\n\n")

            result_file.write("\n-------------------------------")
            result_file.write("\n-------------------------------\n\n")
            result_file.write("Versions flagged as potential malicious:\n\n")

            for version, score in flagged_versions:
                result_file.write(f"{version} with score: {score}\n")

        logging.info(f"Saved result file of comparison of CodeQL sarif files to {dir_comparison_file_path}")

        # Return all flagged package versions
        return flagged_versions, benign_versions

    # Only for testing - not used
    def compare_sarif_result_files_with_location(self):

        dir_package = os.path.join("packages", self.package.name)

        # Result files path
        dir_package_code_ql_results = os.path.join(dir_package, "codeql_results_sarif")

        # Comparison file path
        dir_comparison_file_path = os.path.join(dir_package, f"result_{self.package.name}.txt")

        list_result_files = []

        # Create list of all result files
        for file in os.listdir(dir_package_code_ql_results):
            list_result_files.append(file)

        # Sort the list of files naturally (by version numbers)
        list_result_files = natsorted(list_result_files)

        # Version flagged as malicious
        flagged_versions = []

        severities = {}

        # Load policy if set
        if self.policy:

            with open(self.policy, encoding="utf-8") as f:
                severities = json.load(f)

        if self.package.type == "Benign":
            found_malicious_version = "-"
            malicious_version_score = "-"
        else:
            found_malicious_version = "No"
            malicious_version_score = 0.0

        # Write comparison to file
        with open(dir_comparison_file_path, 'w', encoding="utf-8") as result_file:

            # Compare each two files in a row
            for idx, file in enumerate(list_result_files):

                if len(list_result_files) > idx + 1:

                    # Get names of the package versions (remove "_ql-db.sarif")
                    name_version_1 = file[:len(file) - 12]
                    name_version_2 = list_result_files[idx + 1][:len(list_result_files[idx + 1]) - 12]

                    result_file.write(f"Comparing {name_version_1} to {name_version_2}:\n")
                    result_file.write(f"---------------------------------------------------------\n\n")

                    results_of_report_1 = {}
                    results_of_report_2 = {}

                    severity_sum = 0
                    severity_sum_distinct_queries = 0

                    query_ids = []

                    # Parse sarif report 1
                    with open(os.path.join(dir_package_code_ql_results, file), encoding="utf-8") as f:
                        json_data = json.load(f)

                        if not self.policy:
                            # Get severities for queries
                            for rule in json_data['runs'][0]['tool']['driver']['rules']:
                                if 'security-severity' in rule['properties']:
                                    severities[rule['id']] = float(rule['properties']['security-severity'])

                        for result in json_data['runs'][0]['results']:

                            message = result['message']['text']
                            location = result['locations'][0]['physicalLocation']['artifactLocation']['uri']

                            result_id = f"{message}_{location}"

                            if result_id not in results_of_report_1:
                                results_of_report_1[result_id] = {}
                                results_of_report_1[result_id]['message'] = message
                                results_of_report_1[result_id]['count'] = 1
                                results_of_report_1[result_id]['location'] = location
                                results_of_report_1[result_id]['rule_id'] = result['ruleId']

                                if 'region' in result['locations'][0]['physicalLocation']:

                                    results_of_report_1[result_id]['startLine'] = result['locations'][0][
                                        'physicalLocation']['region']['startLine']

                                    if 'startColumn' in result['locations'][0]['physicalLocation']['region']:

                                        results_of_report_1[result_id]['startColumn'] = result['locations'][0][
                                            'physicalLocation']['region']['startColumn']
                                    else:
                                        results_of_report_1[result_id]['startColumn'] = 'N/A'

                            else:
                                results_of_report_1[result_id]['count'] += 1

                    # Parse sarif report 2
                    with open(os.path.join(dir_package_code_ql_results, list_result_files[idx + 1]),
                              encoding="utf-8") as f:
                        json_data = json.load(f)

                        for result in json_data['runs'][0]['results']:

                            message = result['message']['text']
                            location = result['locations'][0]['physicalLocation']['artifactLocation']['uri']

                            result_id = f"{message}_{location}"

                            if result_id not in results_of_report_2:
                                results_of_report_2[result_id] = {}
                                results_of_report_2[result_id]['message'] = message
                                results_of_report_2[result_id]['count'] = 1
                                results_of_report_2[result_id]['location'] = result['locations'][0][
                                    'physicalLocation']['artifactLocation']['uri']
                                results_of_report_2[result_id]['rule_id'] = result['ruleId']

                                if 'region' in result['locations'][0]['physicalLocation']:

                                    results_of_report_2[result_id]['startLine'] = result['locations'][0][
                                        'physicalLocation']['region']['startLine']

                                    if 'startColumn' in result['locations'][0]['physicalLocation']['region']:

                                        results_of_report_2[result_id]['startColumn'] = result['locations'][0][
                                            'physicalLocation']['region']['startColumn']
                                    else:
                                        results_of_report_2[result_id]['startColumn'] = 'N/A'

                            else:
                                results_of_report_2[result_id]['count'] += 1

                    # Compare results
                    for result_id, data in results_of_report_2.items():
                        if result_id in results_of_report_1:

                            # Compare count
                            if results_of_report_1[result_id]['count'] < results_of_report_2[result_id]['count']:

                                diff = results_of_report_2[result_id]['count'] - results_of_report_1[result_id]['count']

                                location = f"Location: {data['location']}"

                                # Check if startLine and startColumn is in data
                                if 'startLine' in data:
                                    location += f" ({data['startLine']}:{data['startColumn']})"

                                result_file.write(f"{diff} new occurence(s) of finding: Message: \"{result_id}\"; "
                                                  f"{location}; Rule: {data['rule_id']}\n")

                                if data['rule_id'] in severities:
                                    severity_sum += severities[data['rule_id']] * diff

                                    # Only count if new query (id)
                                    if not data['rule_id'] in query_ids:
                                        query_ids.append(data['rule_id'])
                                        severity_sum_distinct_queries += severities[data['rule_id']]

                        else:

                            location = f"Location: {data['location']}"

                            # Check if startLine and startColumn is in data
                            if 'startLine' in data:
                                location += f" ({data['startLine']}:{data['startColumn']})"

                            result_file.write(f"{data['count']} new occurence(s) of finding: Message: "
                                              f"\"{data['message']}\"; "
                                              f"{location}; Rule: {data['rule_id']}\n")

                            if data['rule_id'] in severities:
                                severity_sum += severities[data['rule_id']] * data['count']

                                # Only count if new query (id)
                                if not data['rule_id'] in query_ids:
                                    query_ids.append(data['rule_id'])
                                    severity_sum_distinct_queries += severities[data['rule_id']]

                    result_file.write(f"\nSeverity sum:\n=> All queries: {severity_sum}\n=> Distinct queries: "
                                      f"{severity_sum_distinct_queries}\n")

                    if name_version_2 in self.package.malicious_versions:
                        malicious_version_score = severity_sum_distinct_queries

                    if self.threshold and severity_sum_distinct_queries >= self.threshold:
                        flagged_versions.append((name_version_2, severity_sum_distinct_queries))
                        result_file.write("Flagged as potential malicious.\n")

                        if name_version_2 in self.package.malicious_versions:
                            found_malicious_version = "Yes"

                    result_file.write(f"\n\n")

            result_file.write("\n-------------------------------")
            result_file.write("\n-------------------------------\n\n")
            result_file.write("Versions flagged as potential malicious:\n\n")

            for version, score in flagged_versions:
                result_file.write(f"{version} with score: {score}\n")

        logging.info(f"Saved result file of comparison of CodeQL sarif files to {dir_comparison_file_path}")

        return [self.package.name, len(list_result_files), self.package.type, found_malicious_version,
                len(flagged_versions), round(len(flagged_versions) / len(list_result_files), 2),
                malicious_version_score, self.threshold]

    # ------------------------

    # EVALUATION AND HELPERS
    # ------------------------

    def calculate_average_number_of_code_lines(self):

        # Unpacked package directory
        dir_package_unpacked = os.path.join("packages", self.package.name, "unpacked")

        number_of_versions = len(os.listdir(dir_package_unpacked))

        # Check if we can use cached value
        if os.path.exists(self.package.stats_file):

            # If the file exists, load existing data
            with open(self.package.stats_file, 'r') as json_file:
                existing_data = json.load(json_file)

            # Check if we can use cached value if num of versions matches
            if 'lines_of_code' in existing_data:
                if existing_data['lines_of_code']['versions'] == number_of_versions:
                    return existing_data['lines_of_code']['average_lines_of_code']

        print(f"Calculating average number of code lines for package {self.package.name}...")

        total_number_of_lines = 0

        failed_files = 0

        for version in os.listdir(dir_package_unpacked):
            for root, dirs, files in os.walk(os.path.join(dir_package_unpacked, version)):
                for file in files:
                    if file.endswith('.js') or file.endswith('.ts'):
                        try:
                            with open(os.path.join(root, file), "r", encoding="utf-8") as source_code_file:
                                total_number_of_lines += len(source_code_file.readlines())
                        except UnicodeDecodeError:
                            failed_files += 1
                        except FileNotFoundError:
                            failed_files += 1

        print(f"Failed to open {failed_files} file(s).")

        avg_loc = int(total_number_of_lines / number_of_versions)

        # Check if the file exists
        if os.path.exists(self.package.stats_file):

            # If the file exists, load existing data
            with open(self.package.stats_file, 'r') as json_file:
                existing_data = json.load(json_file)

            existing_data['lines_of_code'] = {
                "versions": number_of_versions,
                "average_lines_of_code": avg_loc
            }

            # Write the updated data back to the JSON file
            with open(self.package.stats_file, 'w') as json_file:
                json.dump(existing_data, json_file)
        else:
            # If the file doesn't exist, create it with initial data
            data = {
                'lines_of_code': {
                    "versions": number_of_versions,
                    "average_lines_of_code": avg_loc
                }
            }
            with open(self.package.stats_file, 'w') as json_file:
                json.dump(data, json_file)

        return avg_loc

    def calculate_update_frequency(self):
        """
            Calculates the average update frequency of all packages
        """

        update_frequencies = []

        for package in self.packages:
            self.package = package
            info_file_path = os.path.join("packages", self.package.name, self.package.name + ".json")

            # Check if local package only
            if not self.package.local:

                # Parse info file
                with open(info_file_path, encoding="utf8") as f:
                    json_data = json.load(f)

                    # Get times
                    times = json_data['time']
                    times_cleaned = []

                    for a_time in times.items():
                        if a_time[0] == "created" or a_time[0] == "modified":
                            print("CREATED OR MODIFIED -> SKIPPED")
                        else:
                            times_cleaned.append(a_time[1])

                    # Convert strings to datetime objects
                    date_format = "%Y-%m-%dT%H:%M:%S.%fZ"
                    date_objects = [datetime.datetime.strptime(date_str, date_format) for date_str in times_cleaned]

                    # Sort the datetime objects
                    sorted_dates = sorted(date_objects)

                    # Convert back to string format if needed
                    sorted_date_strings = [date.strftime(date_format) for date in sorted_dates]

                    # Convert string to datetime objects
                    date_format = "%Y-%m-%dT%H:%M:%S.%fZ"
                    date1 = datetime.datetime.strptime(sorted_date_strings[0], date_format)
                    date2 = datetime.datetime.strptime(sorted_date_strings[len(sorted_date_strings) - 1], date_format)

                    # Calculate the difference
                    date_difference = date2 - date1

                    # Access the difference in days
                    difference_in_days = date_difference.days

                    update_frequencies.append(difference_in_days / len(sorted_date_strings))

                    print(f"The difference in days is: {difference_in_days} days")
                    print(f"Update frequency: {difference_in_days / len(sorted_date_strings)} days")

                    print("")

        print("")
        print(f"Overall frequency: {sum(update_frequencies) / len(update_frequencies)} days")

    def get_package_dependents(self):
        """
            Webscraper for npmjs.com to get number of dependets for package
        """

        # Counter rate limiting
        time.sleep(0.5)

        url = f'https://www.npmjs.com/package/{self.package.name}'
        response = requests.get(url)

        if response:

            soup = BeautifulSoup(response.text, 'html.parser')

            dependents_element = soup.find('a', {'id': 'package-tab-dependents'})
            dependents_text = dependents_element.find('span').text

            return int(dependents_text.replace(',', '').replace(' Dependents', ''))
        else:
            return 0

    def write_package_stats_file(self, stage, versions, time_taken):
        """
            This method creates/updates the statistics json file for each package and pipeline stage.
        """

        # Write data to statistics file
        if versions > 0:

            # Check if the file exists
            if os.path.exists(self.package.stats_file):

                # If the file exists, load existing data
                with open(self.package.stats_file, 'r') as json_file:
                    existing_data = json.load(json_file)

                if stage in existing_data:
                    # Sum up the values
                    existing_data[stage]["versions"] += versions
                    existing_data[stage]["time_taken_seconds"] += time_taken
                else:
                    # If it doesn't exist, create it with initial data
                    existing_data[stage] = {
                        "versions": versions,
                        "time_taken_seconds": time_taken
                    }

                # Write the updated data back to the JSON file
                with open(self.package.stats_file, 'w') as json_file:
                    json.dump(existing_data, json_file)
            else:
                # If the file doesn't exist, create it with initial data
                data = {
                    stage: {
                        "versions": versions,
                        "time_taken_seconds": time_taken
                    }
                }
                with open(self.package.stats_file, 'w') as json_file:
                    json.dump(data, json_file)

    def run_evaluation(self):

        print("Running evaluation of all packages...")

        dir_evaluation_fies = os.path.join("_evaluation")

        # Create evaluation dir
        if not os.path.exists(dir_evaluation_fies):
            os.mkdir(dir_evaluation_fies)

        malicious_packages = []
        benign_packages = []

        malicious_package_files = []

        overall_scanned_versions = 0
        overall_false_positives = 0
        overall_mal_versions = 0
        overall_true_positives = 0

        # Get all malicious package files for calculating FP later
        for packages_path in self.additional_local_packages:
            if 'malicious_packages' in packages_path:
                malicious_package_files = [f for f in os.listdir(packages_path) if os.path.isfile(
                    os.path.join(packages_path, f))]

        # Evaluate all packages
        for package in self.packages:
            self.package = package
            self.package.stats_file = os.path.join("packages", package.name, f"{package.name}_stats.json")

            is_malicious = False

            print(f"Processing NPM package {package.name}.")

            flagged_versions, benign_versions = self.compare_sarif_result_files()

            # Result files path
            dir_package_code_ql_results = os.path.join("packages", self.package.name, "codeql_results_sarif")

            # Count scanned versions of package
            scanned_versions = len(os.listdir(dir_package_code_ql_results))

            # Get number of malicious packages as local files
            true_positives = 0
            num_mal_packages = 0
            mal_score = ""

            for mal_pack_file in malicious_package_files:

                if self.package.name == re.match(r'^(.+?)-\d+\.\d+\.\d+(-\w+)?\.tgz$', mal_pack_file).group(1):
                    num_mal_packages = num_mal_packages + 1
                    is_malicious = True

                    for version, score in flagged_versions:
                        if version == mal_pack_file.replace('.tgz', ''):
                            true_positives = true_positives + 1

                            if mal_score != "":
                                mal_score = f"{mal_score}/{score}"
                            else:
                                mal_score = score

                    # Used to calculate the highest score for a malicious version
                    for version, score in benign_versions:
                        if version == mal_pack_file.replace('.tgz', ''):
                            if mal_score != "":
                                mal_score = f"{mal_score}/{score}"
                            else:
                                mal_score = score

            false_positives = len(flagged_versions) - true_positives

            # Calculate false positive rate of flagged packages -> FPR (false positive rate)
            fp_percentage = round(false_positives / (scanned_versions - num_mal_packages) * 100, 1)

            found_malicious = '\\Checkmark' if num_mal_packages == true_positives else '\\XSolidBrush'

            if is_malicious:
                malicious_packages.append([f"\\texttt{{{self.package.name}}}",
                                           f"{self.calculate_average_number_of_code_lines():,}",
                                           scanned_versions, len(flagged_versions), fp_percentage, mal_score,
                                           found_malicious])
            else:
                benign_packages.append([f"\\texttt{{{self.package.name}}}",  f"{self.get_package_dependents():,}",
                                        f"{self.calculate_average_number_of_code_lines():,}",
                                        f"{scanned_versions:,}", len(flagged_versions),
                                        fp_percentage])

            overall_scanned_versions = overall_scanned_versions + scanned_versions
            overall_false_positives = overall_false_positives + false_positives
            overall_mal_versions = overall_mal_versions + num_mal_packages
            overall_true_positives = overall_true_positives + true_positives

        # Create csv file table for malicious packages
        with open(os.path.join(dir_evaluation_fies, 'table_malicious.csv'), 'w', encoding='utf-8', newline='') as f:

            writer = csv.writer(f, delimiter=";")

            # Write the header
            writer.writerow(['Package Name', 'Avg. LOC', 'Versions', 'Flagged', 'FP', 'Score', 'Found'])

            # Sort data
            malicious_packages.sort(key=lambda x: x[2], reverse=True)

            for data in malicious_packages:
                writer.writerow(data)

        # Create csv file table for benign packages
        with open(os.path.join(dir_evaluation_fies, 'table_benign.csv'), 'w', encoding='utf-8', newline='') as f:

            writer = csv.writer(f, delimiter=";")

            # Write the header
            writer.writerow(['Package Name', 'Dependents', 'Avg. LOC', 'Versions', 'Flagged', 'FP'])

            # Sort data
            benign_packages.sort(key=lambda x: int(x[1].replace(',', '')), reverse=True)

            for data in benign_packages:
                writer.writerow(data)

        print("")

        # Generate further statistics
        self.generate_findings_statistics()
        self.generate_codeql_statistics()
        self.generate_codeql_performance_plots()
        self.generate_roc_curve_plot()

        # General stats
        print("")
        print("General statistics:")
        print(f"Overall scanned versions: {overall_scanned_versions}")
        print(f"Overall false positives: {overall_false_positives}")
        print(f"Overall malicious package versions: {overall_mal_versions}")
        print(f"Overall true positives: {overall_true_positives}")
        print(f"False positive rate: {round(overall_false_positives / overall_scanned_versions, 4)}")

    def generate_findings_statistics(self):

        print("Generating findings statistics...")

        # Stats results
        findings = {}

        if self.policy:
            with open(self.policy, encoding="utf-8") as f:
                policy_json = json.load(f)

            for query in policy_json:
                if query not in findings:
                    findings[query] = (0, 0, 0, list())

        for package in self.packages:
            self.package = package

            package_dir = os.path.join('packages', self.package.name)

            print(f"Processing {package.name}...")

            # Result files path
            dir_package_code_ql_results = os.path.join('packages', self.package.name, "codeql_results_sarif")

            list_result_files = []

            # Create list of all result files
            for file in os.listdir(dir_package_code_ql_results):
                list_result_files.append(file)

            # Sort the list of files naturally (by version numbers)
            list_result_files = natsorted(list_result_files)

            # Compare each two files in a row
            for file in list_result_files:

                # Parse sarif report
                with open(os.path.join(dir_package_code_ql_results, file), encoding="utf-8") as f:
                    json_data = json.load(f)

                    for result in json_data['runs'][0]['results']:
                        query_id = result['ruleId']

                        if query_id not in findings:
                            findings[query_id] = (1, 0, 0, list(package_dir))
                        else:

                            if package_dir not in findings[query_id][3]:
                                # Add package name to list
                                findings[query_id][3].append(package_dir)

                            new_tuple = (findings[query_id][0] + 1, findings[query_id][1], findings[query_id][2],
                                         findings[query_id][3])

                            findings[query_id] = new_tuple

            # Compare each two files in a row
            for idx, file in enumerate(list_result_files):

                if len(list_result_files) > idx + 1:

                    results_of_report_1 = {}
                    results_of_report_2 = {}

                    # Parse sarif report 1
                    with open(os.path.join(dir_package_code_ql_results, file), encoding="utf-8") as f:
                        json_data = json.load(f)

                        for result in json_data['runs'][0]['results']:

                            query_id = result['ruleId']

                            if query_id not in results_of_report_1:
                                results_of_report_1[query_id] = {}
                                results_of_report_1[query_id]['count'] = 1

                            else:
                                results_of_report_1[query_id]['count'] += 1

                    # Parse sarif report 2
                    with open(os.path.join(dir_package_code_ql_results, list_result_files[idx + 1]),
                              encoding="utf-8") as f:
                        json_data = json.load(f)

                        for result in json_data['runs'][0]['results']:

                            query_id = result['ruleId']

                            if query_id not in results_of_report_2:
                                results_of_report_2[query_id] = {}
                                results_of_report_2[query_id]['count'] = 1

                            else:
                                results_of_report_2[query_id]['count'] += 1

                    # Compare results
                    for query_id, data in results_of_report_2.items():
                        if query_id in results_of_report_1:

                            # Compare count
                            if results_of_report_1[query_id]['count'] < results_of_report_2[query_id]['count']:

                                diff = results_of_report_2[query_id]['count'] - results_of_report_1[query_id]['count']

                                new_tuple = (findings[query_id][0],
                                             findings[query_id][1] + diff,
                                             findings[query_id][2] + 1,
                                             findings[query_id][3])
                                findings[query_id] = new_tuple

                        else:

                            new_tuple = (findings[query_id][0],
                                         findings[query_id][1] + data['count'],
                                         findings[query_id][2] + 1,
                                         findings[query_id][3])
                            findings[query_id] = new_tuple

        # csv header
        header = ['Query ID', 'Total Findings', 'Diff. Findings', 'Distinct Diff. Findings']

        # Write stats file as csv
        with open('_evaluation/table_findings.csv', 'w', encoding='utf-8', newline='') as f:

            writer = csv.writer(f, delimiter=";")

            # Write the header
            writer.writerow(header)

            # Convert findings dict to list
            findings_ls = []
            for key, value in findings.items():

                if value[0] > 0:
                    findings_ls.append([key.replace('js/', ''), f"{value[0]:,}", f"{value[1]:,}", f"{value[2]:,}"])

            # Sort data
            findings_ls.sort(key=lambda x: int(x[3].replace(',', '')), reverse=True)

            for find in findings_ls:

                # Write data row
                writer.writerow(find)

        print("")

    def generate_codeql_statistics(self):

        print("Generating CodeQL statistics...")

        packages_stats = []

        total_db_generation_time = 0
        total_db_generation_versions = 0

        total_query_application_time = 0
        total_query_application_versions = 0

        for package in self.packages:
            self.package = package
            self.package.stats_file = os.path.join("packages", package.name, f"{package.name}_stats.json")

            # Check if the file exists
            if os.path.exists(self.package.stats_file):
                # Get stats file for package
                with open(self.package.stats_file, 'r') as json_file:
                    package_stats = json.load(json_file)

                    dir_package_code_ql_results = os.path.join("packages", self.package.name,
                                                               f"codeql_results_{self.result_format}")

                    num_of_versions = len(os.listdir(dir_package_code_ql_results))

                    if 'database_generation' in package_stats:
                        build_db_avg = round(package_stats['database_generation']['time_taken_seconds'] /
                                             package_stats['database_generation']['versions'], 2)
                        total_db_generation_time = total_db_generation_time + package_stats[
                            'database_generation']['time_taken_seconds']
                        total_db_generation_versions = total_db_generation_versions + package_stats[
                            'database_generation']['versions']
                    else:
                        build_db_avg = '-'

                    if 'query_application' in package_stats:
                        apply_queries_avg = round(package_stats['query_application']['time_taken_seconds'] /
                                                  package_stats['query_application']['versions'], 2)
                        total_query_application_time = total_query_application_time + package_stats[
                            'query_application']['time_taken_seconds']
                        total_query_application_versions = total_query_application_versions + package_stats[
                            'query_application']['versions']
                    else:
                        apply_queries_avg = '-'

                    packages_stats.append((self.package.name, f"{num_of_versions:,}",
                                           f"{self.calculate_average_number_of_code_lines():,}", build_db_avg,
                                           apply_queries_avg))

        # csv header
        header = ['Package Name', 'Versions', 'Avg. LOC', 'Avg. Build DB (s)', 'Avg. Apply Queries (s)']

        # Sort by package name
        packages_stats.sort()

        # Write stats file as csv
        with open('_evaluation/table_codeql_stats.csv', 'w', encoding='utf-8', newline='') as f:

            writer = csv.writer(f, delimiter=";")

            # Write the header
            writer.writerow(header)

            for stat in packages_stats:
                writer.writerow(stat)

        print(f"total_db_generation_time: {total_db_generation_time}")
        print(f"total_db_generation_versions: {total_db_generation_versions}")

        print(f"total_query_application_time: {total_query_application_time}")
        print(f"total_query_application_versions: {total_query_application_versions}")

        print(f"Average DB generation time: {round(total_db_generation_time / total_db_generation_versions, 2)}")
        print(f"Average queries application time: "
              f"{round(total_query_application_time / total_query_application_versions, 2)}")
        print(f"Average single query application time: "
              f"{round(total_query_application_time / (total_query_application_versions * 41), 2)}")

        print()

        # Calculate the Spearman correlation coefficient
        rho_db, _ = stats.spearmanr([int(item[2].replace(',', '')) for item in packages_stats],
                                    [item[3] for item in packages_stats])
        rho_queries, _ = stats.spearmanr([int(item[2].replace(',', '')) for item in packages_stats],
                                         [item[4] for item in packages_stats])
        print(f"Spearman correlation coefficient for db: {rho_db}")
        print(f"Spearman correlation coefficient for queries: {rho_queries}")

        rho_db, _ = stats.pearsonr([int(item[2].replace(',', '')) for item in packages_stats],
                                    [item[3] for item in packages_stats])
        rho_queries, _ = stats.pearsonr([int(item[2].replace(',', '')) for item in packages_stats],
                                         [item[4] for item in packages_stats])
        print(f"Pearsonr correlation coefficient for db: {rho_db}")
        print(f"Pearsonr correlation coefficient for queries: {rho_queries}")

        print("")

    def generate_codeql_performance_plots(self):

        print("Generating CodeQL performance plots...")

        # Data for plots
        lines_of_code = []
        times_db = []
        times_queries = []

        # Get data from stats files
        for package in self.packages:
            self.package = package
            self.package.stats_file = os.path.join("packages", package.name, f"{package.name}_stats.json")

            # Check if the file exists
            if os.path.exists(self.package.stats_file):
                with open(self.package.stats_file, 'r') as json_file:
                    stats = json.load(json_file)

                    if 'lines_of_code' in stats and 'database_generation' in stats and 'query_application' in stats:
                        lines_of_code.append(stats['lines_of_code']['average_lines_of_code'])
                        times_db.append(stats['database_generation']['time_taken_seconds'] /
                                        stats['database_generation']['versions'])
                        times_queries.append(stats['query_application']['time_taken_seconds'] /
                                             stats['query_application']['versions'])

        plot_dir = os.path.join("_evaluation", 'plots')

        # Create plot dir
        if not os.path.exists(plot_dir):
            os.mkdir(plot_dir)

        if len(lines_of_code) > 0 and len(times_db) > 0:

            data = pd.DataFrame({'x': lines_of_code, 'y': times_db})

            # Create a regplot
            sns.set_style("darkgrid")
            sns.regplot(x='x', y='y', data=data, label='Package (avg. over all versions)')

            plt.legend(loc='upper left')

            # Label the axes
            plt.xlabel('Lines of code')
            plt.ylabel('Time to generate DB (s)')

            # Save the plot to evaluation dir
            plt.savefig(os.path.join(plot_dir, 'plot_db_generation.svg'), format='svg')

            # Clear the figure
            plt.clf()

        if len(lines_of_code) > 0 and len(times_queries) > 0:

            data = pd.DataFrame({'x': lines_of_code, 'y': times_queries})

            # Create second plot
            sns.regplot(x='x', y='y', data=data, label='Package (avg. over all versions)')

            # Label the axes
            plt.xlabel('Lines of code')
            plt.ylabel('Time to apply queries (s)')

            # Show the legend
            plt.legend(loc='upper left')

            # Save the plot to evaluation dir
            plt.savefig(os.path.join(plot_dir, 'plot_query_application.svg'), format='svg')

            # Clear the figure
            plt.clf()

        # Funktion zur Berechnung der Regressionslinie
        def calculate_regression_line(x, y):
            slope, intercept, _, _, _ = linregress(x, y)
            return slope * x + intercept

        lines_of_code = np.array(lines_of_code)
        times_db = np.array(times_db)
        times_queries = np.array(times_queries)

        # Regressionslinien berechnen
        reg_line1 = calculate_regression_line(lines_of_code, times_db)
        reg_line2 = calculate_regression_line(lines_of_code, times_queries)

        # Diagramm erstellen
        plt.scatter(lines_of_code, times_db, label='Datenpunkt 1')
        plt.scatter(lines_of_code, times_queries, label='Datenpunkt 2')
        plt.plot(lines_of_code, reg_line1, label='Regressionslinie 1', color='blue')
        plt.plot(lines_of_code, reg_line2, label='Regressionslinie 2', color='orange')

        # Legende hinzufügen
        plt.legend()

        # Diagramm anzeigen
        plt.show()

        # Clear the figure
        plt.clf()

        print("")

    def generate_roc_curve_plot(self):
        """
        Generates ROC curve plot with true positive rate vs. false positive rate and optimal threshold
        """

        print("Generating ROC curve plot...")

        # 1 if version malicious or 0 if benign
        y_true = []
        # Severity score of version
        y_score = []

        for package in self.packages:

            print(f"Processing NPM package {package.name}.")

            self.package = package

            flagged_versions, benign_versions = self.compare_sarif_result_files()

            malicious_package_files = []

            # Get all malicious package files
            for packages_path in self.additional_local_packages:
                if 'malicious_packages' in packages_path:
                    malicious_package_files = [f for f in os.listdir(packages_path) if os.path.isfile(
                        os.path.join(packages_path, f))]

            all_versions = flagged_versions + benign_versions

            for name, score in all_versions:
                malicious = 0

                # Check if version is malicious
                for mal_package_file in malicious_package_files:
                    if name == mal_package_file.replace('.tgz', ''):
                        malicious = 1
                        break

                y_true.append(malicious)
                y_score.append(score)

        # Calculate data for roc curve
        fpr, tpr, threshold = metrics.roc_curve(y_true, y_score)

        # Maximize sensitivity + specificity, i.e. tpr + (1-fpr) or just tpr-fpr
        th_optimal = threshold[np.argmax(tpr - fpr)]
        th_optimal_x_value = fpr[list(threshold).index(th_optimal)]
        th_optimal_y_value = tpr[list(threshold).index(th_optimal)]

        print("")
        print("Results of ROC curve:")
        print(f"Data points: {len(y_true)}")
        print(f"Optimal threshold: {y_score[y_score.index(th_optimal)]}")
        print(f"th_optimal_x_value: {th_optimal_x_value}")
        print(f"th_optimal_y_value: {th_optimal_y_value}")

        # Plot ROC curve
        sns.set_style("darkgrid")
        plt.plot(fpr, tpr)
        plt.ylabel('True positive rate')
        plt.xlabel('False positive rate')
        marker_style = dict(marker='o', markersize=8, linestyle='None', color='red', markeredgecolor='darkred',
                            markeredgewidth=1)
        plt.plot(th_optimal_x_value, th_optimal_y_value, **marker_style)

        plt.annotate(f"Optimal threshold ({th_optimal})", (th_optimal_x_value, th_optimal_y_value),
                     xytext=(th_optimal_x_value + 0.2, th_optimal_x_value + 0.4),
                     arrowprops=dict(arrowstyle='-', connectionstyle='arc3', facecolor='red', edgecolor='black'),
                     weight='bold')

        # Save plot as png
        plt.savefig(os.path.join('_evaluation', 'plots', 'plot_roc_curve.svg'), format='svg')

        print("")

    # ------------------------


if __name__ == '__main__':

    # Get config values
    config = configparser.ConfigParser()
    config.read(".config")

    npm_package_names = config.get('Main', 'npm_package_names').split(',') \
        if config.get('Main', 'npm_package_names') else None
    local_package_names = config.get('Main', 'local_package_names').split(',') \
        if config.get('Main', 'local_package_names') else None

    # Tgz package path
    list_of_additional_local_package_paths = config.get('Main', 'list_of_additional_local_package_paths').split(',') \
        if config.get('Main', 'list_of_additional_local_package_paths') else None

    path_to_queries = config.get('Main', 'path_to_queries')
    codeql_result_format = config.get('Main', 'result_format')
    severity_sum_threshold = float(config.get('Main', 'severity_sum_threshold'))

    rescan_packages = True if config.get('Main', 'rescan') == "True" else False
    custom_severity_policy = config.get('Main', 'custom_severity_policy') \
        if config.get('Main', 'custom_severity_policy') else None

    list_of_package_versions_to_skip = config.get('Main', 'package_versions_to_skip').split(',') \
        if config.get('Main', 'package_versions_to_skip') else None

    list_of_packages_to_sort_by_date = config.get('Main', 'packages_to_sort_by_date').split(',') \
        if config.get('Main', 'packages_to_sort_by_date') else None

    check = CheckNPMPackage(package_names=npm_package_names, loc_package_names=local_package_names,
                            queries_path=path_to_queries,
                            additional_local_packages=list_of_additional_local_package_paths,
                            result_format=codeql_result_format, threshold=severity_sum_threshold,
                            rescan=rescan_packages, policy=custom_severity_policy,
                            package_versions_to_skip=list_of_package_versions_to_skip,
                            packages_to_sort_by_date=list_of_packages_to_sort_by_date)

    parser = argparse.ArgumentParser(description='Differential Static Analysis Tool for npm')
    parser.add_argument('--scan', action='store_true', help='Scan all packages defined in the config file.')
    parser.add_argument('--evaluate', action='store_true', help='Run the evaluation of all scanned packages.')
    parser.add_argument('--update-frequency', action='store_true', help='Get overall update frequency of packages.')
    args = parser.parse_args()

    if args.scan:
        check.run_pipeline()
    elif args.evaluate:
        check.run_evaluation()
    elif args.update_frequency:
        check.calculate_update_frequency()
    else:
        # Display help if no valid arguments are provided
        parser.print_help()
