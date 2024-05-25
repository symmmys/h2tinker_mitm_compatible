with import <nixpkgs> { }; 
let 
ps = python311Packages; 
in pkgs.mkShell rec { 
name = "testname"; 
venvDir = "./.venv";
ol_scapy = callPackage ./ol_scapy.nix { buildPythonPackage = ps.buildPythonPackage; can = ps.can; cryptography = ps.cryptography; ecdsa = ps.ecdsa; mock = ps.mock; brotli = ps.brotli; pycrypto = ps.pycrypto; ipython = ps.ipython; isPyPy = false; matplotlib = ps.matplotlib; pyx = ps.pyx; graphviz = ps.graphviz;  };
buildInputs = [
# A Python interpreter including the 'venv' module is required to bootstrap the environment. 
ps.python
ol_scapy
#ps.scapy
# This execute some shell code to initialize a venv in $venvDir before
# dropping into the shell
ps.venvShellHook
ps.python-gitlab
ps.GitPython

# In this particular example, in order to compile any binary extensions they may
# require, the Python modules listed in the hypothetical requirements.txt need
# the following packages to be installed locally:
git
zip
];
#Run this command, only after creating the virtual environment
postVenvCreation = '' 
unset SOURCE_DATE_EPOCH 
'';
#Now we can execute any commands within the virtual environment.
#This is optional and can be left out to run pip manually.
postShellHook = '' 
# allow pip to install wheels 
unset SOURCE_DATE_EPOCH 
''; 
}
