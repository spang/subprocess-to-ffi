#!/usr/bin/env python

import subprocess
import argparse

parser = argparse.ArgumentParser(help="Extract a 7z archive")
parser.add_argument('filename')

args = parser.parse_args()

subprocess.check_call(['7z', 'x', args.filename])
