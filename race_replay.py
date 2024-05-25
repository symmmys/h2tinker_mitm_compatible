import h2tinker as h2
import time
import scapy.contrib.http2 as scapy
import logging
from mitmproxy import command
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.log import ALERT
from mitmproxy.script import concurrent
import typing
import abc
import collections
import asyncio

class RaceReplay:
    #WIP, but the goal here is to take a sequence of compatible flows and string them all together into
    #a single-packet attack. This will allow building of the attack using the mitmproxy UI.
    #intended use is to run on @marked
    @command.command("race_replay")
    def race_replay(self, flows: collections.abc.Sequence[flow.Flow]) -> None:
        if len(flows) > 0:
            this_logger = logging.getLogger(__name__)
            conn = h2.H2TLSConnection(this_logger)
            request_naught = flows[0].request
            this_url = flows[0].request.url
            logging.info(f"[RaceReplay] Connecting to: {request_naught.host}")
            conn.setup( "portswigger.net")
            logging.info(f"[RaceReplay] Established connection with: {request_naught.host}")

            # We gather the final DATA frames here
            final_frames = []
            flow_index = 0

            # Generate 10 valid client stream IDs
            for i in h2.gen_stream_ids(len(flows)):
                this_flow = flows[flow_index]
                flow_index = flow_index + 1
                if isinstance(this_flow, http.HTTPFlow):
                    # Create request frames for POST /race
                    req = conn.create_request_frames(this_flow.request.method, this_flow.request.path , i, this_flow.request.headers,this_flow.request.content)
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

addons = [RaceReplay()]
