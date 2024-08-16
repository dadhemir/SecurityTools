# installer.py
import subprocess

def install_requirements():
  requirements_file = 'requirements.txt'
  subprocess.run(['pip3', 'install', '-r', requirements_file])

if __name__ == '__main__':
  install_requirements()