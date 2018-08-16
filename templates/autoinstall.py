import sys
import os


def process(cmd):
    if os.system(cmd) != 0:
        print('installation failed')
        exit(1)


def main():
    import urllib.request
    import tempfile
    import zipfile
    import shutil

    login_key = "{{ login_key }}"
    zip_url = "{{ zip_url }}"
    zip_file = tempfile.mkstemp()[1]
    target_directory = "/usr/share/simple-guardian"

    print('obtaining latest release from %s' % zip_url)
    urllib.request.urlretrieve(zip_url, zip_file)

    print('extracting zip content into temporary folder')
    extracted_dir = tempfile.mkdtemp()
    with zipfile.ZipFile(zip_file, "r") as zip_ref:
        zip_ref.extractall(extracted_dir)
    os.unlink(zip_file)
    source_dir = os.path.join(extracted_dir, os.listdir(extracted_dir)[0])
    files_from_to = {os.path.join(source_dir, filename): os.path.join(target_directory, filename)
                     for filename in os.listdir(source_dir)}

    print('moving files into %s' % target_directory)
    for file_from, file_to in files_from_to.items():
        parent_dir = os.path.abspath(os.path.join(file_to, os.path.pardir))
        if not os.path.isdir(parent_dir):
            os.makedirs(parent_dir)
        shutil.move(file_from, file_to)
    shutil.rmtree(extracted_dir)

    print('creating simple-guardian user')
    process("useradd simple-guardian")
    print('adding simple-guarian to adm group')
    process("usermod -a -G adm simple-guardian")
    print('giving folder permissions to simple-guardian')
    process("chown -R simple-guardian %s" % target_directory)
    print('creating venv')
    process("%s -m venv %s" % (sys.executable, os.path.join(target_directory, 'venv')))
    pip_path = os.path.join(target_directory, 'venv', 'bin', 'pip')
    print('installing requirements')
    process("%s install -r %s" % (pip_path, os.path.join(target_directory, 'requirements.txt')))
    print('adding client simple-guardian-client')
    with open('/usr/bin/simple-guardian-client', 'w') as f:
        f.write("""#!/bin/bash
cd "%s"
./venv/bin/python simple-guardian.py client "$@"
""" % target_directory)
    process("chmod +x /usr/bin/simple-guardian-client")
    print('loging in with server')
    process("simple-guardian-client login \"%s\"" % login_key)
    print('installing system service')
    with open('/etc/systemd/system/simple-guardian.service', 'w') as f:
        f.write("""[Unit]
Description=Simple-guardian service
After=network.target

[Service]
Type=simple
User=simple-guardian
WorkingDirectory=%s
ExecStart=%s/venv/bin/python simple-guardian.py
Restart=on-failure

[Install]
WantedBy=multi-user.target""" % (target_directory, target_directory))
    print('starting service')
    process('sudo service simple-guardian start')
    print('you are protected now!')


if sys.version_info[0] != 3:
    print('you must run this auto installer with Python 3')
    exit(1)
if os.geteuid() != 0:
    print('you must give this script root\'s rights')
    exit(1)
if os.system("%s -m pip -V" % sys.executable) != 0 and os.system("%s -m ensurepip" % sys.executable) != 0:
    print('you must install pip AND ensurepip (venv) before running this script')
    exit(1)
main()
