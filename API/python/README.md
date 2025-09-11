This is a python project, in order for me to learn more about APIs.
Tested on Linux Ubuntu 24.04.2 LTS with FastAPI framework.

# How to use it

- Copy the 2 files on your local environment
- Make sure python3 is already installed with pip and venv (or launch "sudo apt install -y python3 python3-pip python3-venv")
- Create a virual environment (python -m venv .venv)
- Activate this virtual env. (source .venv/bin/activate)
- Install the requirements (pip install -r requirements.txt)
- Launch it! (python main.py)

# Security WARNING

This script should be run on a TEST environment ONLY because:
- it listens on your server's IP address, not on 127.0.0.1
- it works via HTTP, not HTTPS
- admin password is easily available

 => It will be better to install a reverse proxy in order to secure the traffic

# Here is what you should get

FYI, it's running on a VM machine.

<img width="1796" height="1480" alt="image" src="https://github.com/user-attachments/assets/b4fde27c-2b8e-4e24-8711-0b2f9e271e7d" />

