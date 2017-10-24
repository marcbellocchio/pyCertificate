# pyCertificate
generate certificates from openssl using command line or script in text format:

tested on windows 10 64bit version and  OpenSSL 1.0.2h 3 May 2016

features
--------
generate certificates and associated RSA keys pair
allow to generate a certificate chain from root to device
allow to a fast generation of a 3 levels chain: root, intermediate, device


Default settings:
----------------
hash is sha256
rsa key length is 2048
rsa private key is always encrypted using aes 128 bit
object type are [ 'Root', 'Intermediate', 'Device']
a python class for configuring the tool owns the settings
one configuration file (txt format) per certificate is needed as input for openssl 
a log file is created to trace the generation steps (infos, warnings and errors levels)

prerequisites:
--------------
install openssl on the PC
install python on the pc (python >=3.5)
intall the python files from the 

configuration files
-------------------

manual use
----------
The tool can be fully used from cli.
help can be invoked from the cli to determine the list of available functions
the functions cannot be called in random order, the openssl faq explains how to chain the features.
The sample scripts show how to chain the main functions to generate or chain certificates

scripts
-------
the script option allows to call the functions of the tool, to automatically generate certificates from previous generated certificates.
Once root and intermediater are generated, generating a device certificate for a customer or a different server is easy

Samples scripts
----------------
script_chain3levels.txt
script_root.txt
script_inter.txt
script_device.txt

Samples commands
----------------
manual:
<path to python programm> <path to the main class file>\OpensslInherit.py

automatic:
<path to python programm> <path to the main class file>\OpensslInherit.py <script file>


Windows
--------
executable created with cx_Freeze 5.0.2
issue solved when installing a .whl package (error message not wupported .whl file)
add to a python file
inport pip
print(pip.pep425tags.get_supported())
check for a list like this:
[('cp35', 'cp35m', 'win32'), ('cp35', 'none', 'win32'), ('py3', 'none', 'win32'), ('cp35', 'none', 'any'), ('cp3', 'none', 'any'), ('py35', 'none', 'any'), ('py3', 'none', 'any'), ('py34', 'none', 'any'), ('py33', 'none', 'any'), ('py32', 'none', 'any'), ('py31', 'none', 'any'), ('py30', 'none', 'any')]

remane accordingly the .whl donwload for your platform

make an executable file
<python> -m pip install pyinstaller
pyinstaller <main class file>

Linux
-----
not tested
