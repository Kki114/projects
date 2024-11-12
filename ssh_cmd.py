import paramiko

title = 'Enter Credentials'
# Print 'title', with 5 #'s on each side and a second endline after string is printed
print(f"{title:#^{len(title) + 10}}", end='\n\n')

def ssh_command(ip, port, user, passwd, cmd):

    output_title = 'Output'
    print(f'{output_title:#^{len(output_title) + 10}}', end='\n\n')
    
    # client initialization
    client = paramiko.SSHClient()

    # set policy for connection
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(ip, port=port, username=user, password=passwd)

    *_, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print(f'{output}')
        for line in output: print(line.strip())

if __name__ == '__main__':
    import getpass

    #user = getpass.getuser()
    user = input('Username: ')
    password = getpass.getpass()

    ip = input('Enter server IP: ') or '192.168.1.100'
    port = input('Enter port or <CR>: ') or 2222
    cmd = input('Enter command or <CR>: ') or 'id'

    ssh_command(ip, port, user, password, cmd)