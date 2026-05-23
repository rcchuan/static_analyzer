"""
Build script - packages the analyzer as a standalone executable
Usage: python build.py
"""
import subprocess
import sys
import os


def build():
    print("=" * 60)
    print("  MultiLang Static Code Analyzer - Build Script")
    print("=" * 60)

    # Install pyinstaller if needed
    print("\n[1/3] 检查 PyInstaller...")
    try:
        import PyInstaller
        print(f"  PyInstaller 已安装: {PyInstaller.__version__}")
    except ImportError:
        print("  正在安装 PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Run pyinstaller
    print("\n[2/3] 编译打包...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "StaticAnalyzer",
        "--add-data", f"core{os.pathsep}core",
        "--add-data", f"parsers{os.pathsep}parsers",
        "--add-data", f"analysis{os.pathsep}analysis",
        "--add-data", f"gui{os.pathsep}gui",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "ast",
        "main.py"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("\n[3/3] ✅ 打包成功!")
        print(f"  可执行文件位于: dist/StaticAnalyzer" +
              (".exe" if sys.platform == "win32" else ""))
    else:
        print(f"\n❌ 打包失败:\n{result.stderr[-2000:]}")
        sys.exit(1)


if __name__ == "__main__":
    build()
