import sys
import socket
import threading

# Filters the hex characters to only those that can be represented as a single character with length of 3, e.g., 'A' is length 3
# All other characters are replaced with '.'
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])


def hexdump(src, length=16, show=True):

    # Checks is 'src' is of type 'bytes'
    # If true, decode 'src'
    if isinstance(src, bytes):
        src = src.decode()
    
    # Creates empty list 'results'
    results = list()

    # Creates for loop with range 0 to the length of 'src' and steps by 'length'=16
    for i in range(0, len(src), length):

        # Breaks apart 'src' into chunks of length 16 or less
        word = str(src[i:i+length])

        # Checks if character 'word' is valid with 'HEX_FILTER'
        printable = word.translate(HEX_FILTER)

        # Formatting for hexadecimal and joined by an empty space between each characters hex representation
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3

        # Appends each 'hexa' character to list 'results'k
        # {i:04x} formats 'i'. '0' adds leading 0's,'4' makes output of length 4 and 'x' uses lowercase hex representation, i.e., 'K' would become '004b'
        # {hexa:<{hexwidth}} prints 'hexa', ':<' Left aligned, with space 'hexwidth' length (48)
        # {printable} adds the value of 'printable' into 'results'
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    
    if show:

        # Checks if show==True; prints each line from 'results'
        for line in results:
            print(line)
    else:

        # If show != True, returns the full list 'results'
        return results


# Used for receiving local and remote data
# Passed socket object as 'connection'
def receive_from(connection):
    
    # Initialize a byte string as a buffer
    buffer = b""

    # Set a timeout after 10 seconds have passed
    connection.settimeout(20)

    # Try statement to receive data
    try:
        while True:

            # Receive up to 4096 bytes of data until there's no more data or timeout
            data = connection.recv(4096)

            # Checks if there's any data being received
            # Breaks out of loop if there is nothing
            if not data:
                break
            
            # Appends data to 'buffer'
            buffer += data

    # Catches exceptions and prints generic error script        
    except Exception as e:
        #print(f'Error: {e}')
        pass
    
    # Returns 'buffer' of type bytes to caller (local or remote)
    return buffer


def request_handler(buffer):
    # perform packet modifications (e.g. fuzzing, testing for auth issues, finding creds, etc.)
    return buffer


def response_handler(buffer):
    # perform packet modifications (e.g. fuzzing, testing for auth issues, finding creds, etc.)
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    
    # Create socket object IPv4 and TCP
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to remote socket
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
    
    remote_buffer = response_handler(remote_buffer)

    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." %len(remote_buffer))
        client_socket.send(remote_buffer)
    

    while True:
        local_buffer = receive_from(client_socket)

        if len(local_buffer):
            line = "[==>] Received %d bytes from localhost." %len(local_buffer)
            print(line)
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")
        
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote host." %len(remote_buffer))
            hexdump(remote_buffer)
            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    
    # Create 'server' socket object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind to the localhost
    try:
        server.bind((local_host, local_port))
    
    # Catch any exceptions and print error messages
    except Exception as e:
        print('problem on bind: %r' % e)

        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))

        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    # Listen on bound socket
    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)

    while True:

        # Accept new connection
        client_socket, addr = server.accept()

        # Print out the local connection information
        line = "> Received incoming connection from %s:%d" % (addr[0], addr[1])
        print(line)

        # Start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()


def main():
    
    if len(sys.argv[1:]) != 5:
        # "end=' '" is used to tell Python to add a space at the end of print statement instead of a newline
        print("Usage: ./proxy.py [localhost] [localport]", end=' ')  
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)
    
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()