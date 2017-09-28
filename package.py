#!/usr/bin/env python

import sys
import os
import argparse
import tempfile
import zipfile
import shutil
import subprocess
import urllib
import shutil
import errno    

from functools import partial


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

class GitPythonDependency(object):
    def __init__(self, url):
        self.dir = tempfile.mkdtemp()
        self.url = url
        self.fetch()

    def destroy(self):
        shutil.rmtree(self.dir)

    def fetch(self):
        cmd = ("git", "clone", self.url, self.dir)
        subprocess.check_call(cmd)

    def install(self, path, bits):
        env = {"PYTHONPATH": os.path.join(path, "lib/python2.7/site-packages")}
        cmd = ("python", "setup.py", "install", "--prefix", path)
        subprocess.check_call(cmd, cwd = self.dir, env = env)

class YaraPythonWinDependency(object):
    YARA_PYTHON_32BIT_URL = "https://www.dropbox.com/sh/umip8ndplytwzj1/AADuLJ_5Sa279u0fKplRbkOZa/yara-python-3.6.1.win32-py2.7.exe?dl=1"
    YARA_PYTHON_64BIT_URL = "https://www.dropbox.com/sh/umip8ndplytwzj1/AADetRlpZd-Nd4slSkud78Qxa/yara-python-3.6.3.win-amd64-py2.7.exe?dl=1"

    def __init__(self):
        handle, self.installer_32bit = tempfile.mkstemp()
        os.close(handle)
        handle, self.installer_64bit = tempfile.mkstemp()
        os.close(handle)
        cmd = ("curl", "-L", "-o", self.installer_32bit, self.YARA_PYTHON_32BIT_URL)
        subprocess.check_call(cmd)
        cmd = ("curl", "-L", "-o", self.installer_64bit, self.YARA_PYTHON_64BIT_URL)
        subprocess.check_call(cmd)

    def destroy(self):
        os.unlink(self.installer_32bit)
        os.unlink(self.installer_64bit)

    def install(self, path, bits):
        if bits == 32:
            cmd = ("unzip", "-j", "-d", os.path.join(path, "lib/python2.7"), self.installer_32bit, "PLATLIB/yara.pyd")
        else:
            cmd = ("unzip", "-j", "-d", os.path.join(path, "lib/python2.7"), self.installer_64bit, "PLATLIB/yara.pyd")
        # unzip will return status 1 because the file is a self-extracting archive, where the self extractor
        # is detected as junk 
        subprocess.call(cmd)

class YaraPythonLinuxDependency(object):
    YARA_PYTHON_GIT_URL = "https://github.com/VirusTotal/yara-python"

    def __init__(self):
        self.yara_python_dir = tempfile.mkdtemp()
        cmd = ("git", "clone", "--recursive", self.YARA_PYTHON_GIT_URL, self.yara_python_dir)
        subprocess.check_call(cmd)

    def destroy(self):
        shutil.rmtree(self.yara_python_dir)

    def install(self, path, bits):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.join(path, "lib/python2.7/site-packages")
        if bits == 32:
            env["CFLAGS"] = "-m32"
            env["CXXFLAGS"] = "-m32"
            env["LDFLAGS"] = "-m32"
        cmd = ("python", "setup.py", "clean")
        subprocess.check_call(cmd, cwd = self.yara_python_dir)
        if os.path.exists(os.path.join(self.yara_python_dir, "build")):
            shutil.rmtree(os.path.join(self.yara_python_dir, "build"))
        cmd = ("python", "setup.py", "install", "--prefix", path)
        subprocess.check_call(cmd, cwd = self.yara_python_dir, env = env)

def get_plugin_git_version():
    try:
        return subprocess.check_output(["git", "describe", "--tags"]).split("\n")[0].strip() or "devel"
    except OSError:
        return "unknown"

def main(args):
    my_directory = os.path.split(os.path.abspath(__file__))[0]
    version = get_plugin_git_version()

    ply = GitPythonDependency("https://github.com/dabeaz/ply")
    idann = GitPythonDependency("https://github.com/williballenthin/ida-netnode")

    yara_python_win = YaraPythonWinDependency()
    yara_python_linux = YaraPythonLinuxDependency()

    def fetch_windows_dependencies(path, bits):
        ply.install(os.path.join(path, "python"), bits)
        idann.install(os.path.join(path, "python"), bits)
        yara_python_win.install(os.path.join(path, "python"), bits)

    def fetch_linux_dependencies(path, bits):
        ply.install(os.path.join(path, "python"), bits)
        idann.install(os.path.join(path, "python"), bits)
        yara_python_linux.install(os.path.join(path, "python"), bits)

    architectures = [
        ("universal", lambda x: None),
        ("windows_32bit_fat", partial(fetch_windows_dependencies, bits = 32)),
        ("windows_64bit_fat", partial(fetch_windows_dependencies, bits = 64)),
        ("linux_32bit_fat", partial(fetch_linux_dependencies, bits = 32)),
        ("linux_64bit_fat", partial(fetch_linux_dependencies, bits = 64))]


    for arch, fetcher in architectures:
        directory = tempfile.mkdtemp()
        mkdir_p(os.path.join(directory, "plugins"))
        mkdir_p(os.path.join(directory, "python/lib/python2.7/site-packages"))
        print("my_directory: {}".format(my_directory))
        plugin_files = subprocess.check_output(("git", "ls-files"), \
                    cwd = os.path.join(my_directory, "plugin"), 
                    env = os.environ).strip().split("\n")
        for f in plugin_files:
            destpath = os.path.join(directory, "plugins", os.path.split(f)[0])
            mkdir_p(destpath)
            shutil.copy2(os.path.join(my_directory, "plugin", f), os.path.join(directory, "plugins", f))
        fetcher(directory)
        files = [os.path.join(d, f) for d, _, files in os.walk(directory) for f in files]
        with zipfile.ZipFile(os.path.join(args.output, "casc_{}_{}.zip".format(version, arch)), "w") as archive:
            for path in files:
                archive.write(path, os.path.relpath(path, directory))
        shutil.rmtree(directory)

    ply.destroy()
    idann.destroy()
    yara_python_win.destroy()
    yara_python_linux.destroy()

def parse_args():
    parser = argparse.ArgumentParser(description = "Create an installable archive of the CASC plugin")
    parser.add_argument("--output", type = str, default = os.getcwd(), help = "Output directory")

    return parser.parse_args()

if __name__ == "__main__":
    main(parse_args())

