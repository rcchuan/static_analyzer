"""
Multi-Language Static Code Analyzer - Main Entry Point
"""
import sys
import os

# Ensure correct path resolution for both script and PyInstaller exe
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, base_dir)

from gui.app import StaticAnalyzerApp


def main():
    app = StaticAnalyzerApp()
    app.run()


if __name__ == "__main__":
    main()
