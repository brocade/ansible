import paramiko

def ssh_and_configure(login, password, ipaddr, hostkeymust, cmdstr, expected):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if not hostkeymust:
        ssh.set_missing_host_key_policy(paramiko.client.WarningPolicy())
    try:
        ssh.connect(ipaddr, username=login, password=password)
    except paramiko.ssh_exception.AuthenticationException:
        return -1, "invalid name/password"
    except Exception as e:
        return -2, "skiiping due to error" + str(e)

    e_stdin, e_stdout, e_stderr = ssh.exec_command(cmdstr)
    e_resp = e_stdout.read().decode()
    ssh.close()

    if isinstance(expected, list):
        found = False
        for line in expected:
            if line in e_resp:
                found = True
                break
        if found:
            return 0, e_resp
        else:
            return -1, e_resp
    else:
        if expected == "showcommand":
            return 0, e_resp
        elif expected == "":
            if len(e_resp) == 0:
                return 0, e_resp
            else:
                return -1, e_resp
        else:
            if expected in e_resp:
                return 0, e_resp
            else:
                return -1, e_resp
