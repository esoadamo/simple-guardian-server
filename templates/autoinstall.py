import sys
import os
import urllib.request
import tempfile
import zipfile
import shutil
from subprocess import check_call, CalledProcessError

login_key = "{{ login_key }}"
zip_url = "{{ zip_url }}"
zip_file = tempfile.mkstemp()[1]
target_directory = "/usr/share/simple-guardian"


def run(cmd):
    try:
        check_call(cmd)
    except CalledProcessError:
        print('ERRROR: running command "%s" failed for some reason' % cmd)
    except OSError:
        print('ERRROR: running command "%s" failed - the command was not found' % cmd)


# CHECK REQUIREMENTS
# - check Python 3 is ued
if sys.version_info[0] != 3:
    print('you must run this auto installer with Python 3')
    print("ERROR: CHECKING REQUIREMENTS FAILED")
    exit(1)
# - check root right are available
if os.geteuid() != 0:
    print('you must give this script root\'s rights')
    print("ERROR: CHECKING REQUIREMENTS FAILED")
    exit(1)
# - check that pip and venv are installed
try:
    check_call([sys.executable, '-m', 'pip', '-V'])
    check_call([sys.executable, '-m', 'ensurepip'])
except CalledProcessError:
    print('it seems that pip/venv is/are missing. I will try to compensate that')
    try:
        check_call(['apt', 'install', '-y', 'python3-pip', 'python3-venv'])
    except CalledProcessError:
        print("that didn't make it better, this one is on you")
        print("try to install python3-pip python3-venv on Ubuntu/Debian based systems")
        print("ERROR: CHECKING REQUIREMENTS FAILED")
        exit(1)
print('requirements checked, all OK')

print('obtaining latest release from %s' % zip_url)
urllib.request.urlretrieve(zip_url, zip_file)

print('extracting zip content into temporary folder')
extracted_dir = tempfile.mkdtemp()
with zipfile.ZipFile(zip_file, "r") as zip_ref:
    zip_ref.extractall(extracted_dir)
os.unlink(zip_file)

print('running simple-guardian\'s installer')
run([sys.executable, '{0}/install.py'.format(extracted_dir)])

print('removing source files')
shutil.rmtree(extracted_dir)

print('logging in with server')
run(['simple-guardian-client', 'login', login_key])

print('removing packed profiles')
os.unlink(target_directory + "/data/profiles/default.json")

print('restarting service')
run(['service', 'simple-guardian', 'restart'])

print('all done')
