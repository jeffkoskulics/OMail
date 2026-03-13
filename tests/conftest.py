import sys
import os

# Manually add the src directory to sys.path to ensure tests can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))