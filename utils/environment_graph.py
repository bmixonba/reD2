import pandas as pd
import sys
import os 
from os import listdir
from os.path import join

def unzip_apk(apk_name):
    """ """

def get_files(apk_loc):
    """ """

def get_file_type_using_file_cmd(files):
    """ """

def get_file_type_using_magic(files):
    """ """

def get_file_types(files):
    """ """
    files = get_file_type_using_file_cmd(files)
    files = get_file_type_using_magic(files)
    return files

def get_file_entropy(files):
    """ """

def get_file_references(files):
    """ """

def build_graph(apk_name):
    """
    1. Unzip file
    2. Build map of files to metadata (focus on SO files, and files in asset, lib, and res directories)

        (type according to `file` command, type using magic, entropy, list of functions that reference it)

    """
    apk_loc = unzip_apk(apk_name)
    files = get_files(apk_loc)
    files = get_file_types(files)
    files = get_file_entropy(files)
    files = get_file_references(files)

def test_apk_analyzer(apk_name, outdir, jadx_path):
    """ """
    import apk

    apk_info, decompiled_dir, interesting_files, dependencies = apk.analyze_apk(apk_name, outdir, jadx_path)

def run_test_apk_analyzer():

    apk_name = sys.argv[1]
    outdir = sys.argv[2]
    jadx_path = "/home/conntrack/cryptosluice/apks/bin/jadx"
    test_apk_analyzer(apk_name, outdir, jadx_path)

def main():
    """ """
    run_test_apk_analyzer()

if __name__ == '__main__':
    main()
