
import h2tinker as h2
import time
import scapy.contrib.http2 as scapy
import logging

this_logger = logging.getLogger(__name__)

conn = h2.H2TLSConnection(this_logger)
conn.setup('tic.ix.tc')
# We gather the final DATA frames here
final_frames = []



test_headers = ((bytes("user-agent",'utf-8'), bytes("Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",'utf-8')),
                (bytes("accept",'utf-8'), bytes("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",'utf-8')),
                (bytes("accept-language",'utf-8'), bytes("en-US,en;q=0.5",'utf-8')),
                (bytes("accept-encoding",'utf-8'), bytes("gzip, deflate, br",'utf-8')),
                (bytes("upgrade-insecure-requests",'utf-8'), bytes("1",'utf-8')))

# Generate 10 valid client stream IDs
for i in h2.gen_stream_ids(10):

    # Create request frames for POST /race
    req = conn.create_request_frames('GET', '/about/', i, test_headers)
    # Remove END_STREAM flag from HEADERS frame which is always first
    req.frames[0].flags.remove('ES')
    # Send the request frames
    conn.send_frames(req)
    # Create the final DATA frame using scapy and store it
    final_frames.append(scapy.H2Frame(flags={'ES'}, stream_id=i) / scapy.H2DataFrame())

# Sleep a little to make sure previous frames have been delivered
time.sleep(5)
# Send the final frames to complete the requests
conn.send_frames(*final_frames)

# Remain listening on the connection
conn.infinite_read_loop()
