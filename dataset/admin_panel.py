import subprocess


def ping_server(user_input_ip):
    command = f"ping -c 4 {user_input_ip}"
    subprocess.run(command, shell=True)


def get_system_info():
    return subprocess.run("uname -a", shell=True, capture_output=True).stdout
