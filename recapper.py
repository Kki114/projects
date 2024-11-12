
from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

# Where to send images to
OUTDIR = '/home/khari/Pictures'

# Where to get .pcap files from
PCAPS = "\'/home/khari/Documents/python/scapy_project/BHP - Chapter 4\'"

# Initialize namedtuple called 'Response' for the 'header' and 'payload' of HTTP traffic
Response = collections.namedtuple('Response', ['header', 'payload'])

# Takes raw HTTP traffic and spits out the headers
def get_header(payload):
    
    try:
        # Looks for portion of payload from the beginning to the end, which is '\r\n\r\n'
        header_raw = payload[:payload.index(b'\r\n\r\n') + 2]

    # If payload doesn't match, ValueError is caught and 'None' is returned    
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None
    
    # Create a dictionary 'header' from the decoded payload
    # Splitting on the colon so the 'key' is the part before the colon and 'value' is after colon
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    
    # If 'header' has no key called "Content-Type", then return 'None'
    # Says "header doesn't contain the data we want to extract"
    if 'Content-Type' not in header:
        return None
    
    # Return dictionary 'header'
    return header

# Takes HTTP response and extracts "Content-Type"='image'
def extract_content(Response, content_name='image'):
    
    content, content_type = None, None

    # If response contains an image, 'Content-Type' will have 'image' in it. E.g., 'image/png' or 'image/jpg'
    if content_name in Response.header['Content-Type']:
        content_type = Response.header['Content-Type'].split('/')[1]    # 'If 'image/png'; content_type = 'png'
        content = Response.payload[Response.payload.index(b'\r\n\r\n') + 4:]

        # If content has been encoded, decompress using 'zlib' module
        if 'Content-Encoding' in Response.header:
            if Response.header['Content-Encoding'] == "gzip":
                content = zlib.decompress(Response.payload, zlib.MAX_WBITS | 32)
            elif Response.header['Content-Encoding'] == "deflate":
                content = zlib.decompress(Response.payload)
    
    # Return a tuple of 'content' and 'content_type'
    return content, content_type

class Recapper:
    #
    def __init__(self, fname):

        # Initialize object with the name of pcap file to read
        pcap = rdpcap(fname)

        # Take advantage of Scapy feature, that automatically separates each TCP session into a dictionary of each complete TCP stream
        self.sessions = pcap.sessions()

        # Create an empty list to fill with responses from pcap file
        self.responses = list()

    # Search packets for each separate 'Response' and add each one to 'self.responses' list
    def get_responses(self):

        # Iterate over 'sessions' dictionary
        for session in self.sessions:

            # Initialize bytes buffer 'payload'
            payload = b''

            # Iterate over the packets within 'sessions dictionary
            for packet in self.sessions[session]:
                try:

                    # Filter packets by source port or destination port = 80
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:

                        # Add payload from packets to buffer 'payload'
                        payload += bytes(packet[TCP].payload)

                # If we fail to append to buffer 'payload, most likely there is no TCP in the packet
                except IndexError:
                    sys.stdout.write('x')
                    sys.stdout.flush()

                # If 'payload' is not empty
                if payload:

                    # Pass 'payload' to HTTP header-parsing function
                    header = get_header(payload)

                    if header is None:
                        continue

                    # Append the response to the 'self.responses' list
                    self.responses.append(Response(header=header, payload=payload))

    # Writes the image(s) to disk
    def write(self, content_name):

        # Iterate over responses
        for i, response in enumerate(self.responses):

            # Extract the content of the responses
            content, content_type = extract_content(response, content_name)
            
            # Write 'content' to file
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)

if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'arper.pcap')
    recapper = Recapper(pfile)
    recapper.get_responses()
    recapper.write('image')
