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


this_logger = logging.getLogger(__name__)
logging.basicConfig(filename='mitmproxy-dep_stream_replay.log', level=logging.DEBUG, force=True)

class DepReplay:
    #WIP, but the goal here is to take a sequence of compatible flows and string them all together into
    #a single-packet attack. This will allow building of the attack using the mitmproxy UI.
    #intended use is to run on @marked
    @command.command("dep_stream_replay")
    def dep_stream_replay(self, flows: collections.abc.Sequence[flow.Flow]) -> None:
        if len(flows) > 0:
            conn = h2.H2TLSConnection(this_logger)
            request_naught = flows[0].request
            this_url = flows[0].request.url
            logging.info(f"[DepReplay] Connecting to: {request_naught.host}")
            conn.setup( request_naught.host )
            logging.info(f"[DepReplay] Established connection with: {request_naught.host}")

            # We gather the final DATA frames here
            final_frames = []
            flow_index = 0

            # Generate 10 valid client stream IDs
            for i in h2.gen_stream_ids(len(flows)):
                this_flow = flows[flow_index]
                flow_index = flow_index + 1
                if isinstance(this_flow, http.HTTPFlow):
                    
                    #withold the last byte of content data
                    req = conn.create_request_frames(this_flow.request.method, this_flow.request.path , i, headers=this_flow.request.headers,body=this_flow.request.content[:-1])

                    # Remove END_STREAM flag from any frames that have it set:
                    for frame in req.frames:
                        if 'ES' in frame.flags:
                            frame.flags.remove('ES')
                    # Send the request frames
                    conn.send_frames(req)
                    # Create the final DATA frame using scapy and store it
                    final_frames.append(scapy.H2Frame(flags={'ES'}, stream_id=i) / scapy.H2DataFrame())

            # Sleep a little to make sure previous frames have been delivered
            time.sleep(0.1)
            # Send the final frames to complete the requests
            conn.send_frames(*final_frames)

            # Remain listening on the connection
            conn.infinite_read_loop()

            #Dependent streams sync
            # Generate enough stream IDs
            num_ids = len(flows) + 10
            sids = h2.gen_stream_ids(num_ids)
            # 10 IDs will be used for the dependency chain
            chain_sids = sids[:10]
            #The rest of the IDs will be used for the concurrent race requests
            race_sids = sids[10:]

            # Here we gather the dep chain requests
            dep_chain_reqs = []
            # THis is the root of the chain, it doesn't depend on any request
            root_req = conn.create_request_frames('POST', '/long', chain_sids[0])
            dep_chain_reqs.append(root_req)

            for i in range(len(chain_sids) - 1):
                # Stream ID of the previous link in the chain on which this request will depend
                prev_sid = chain_sids[i]
                # Stream ID of this request
                current_sid = chain_sids[i + 1]
                # Create the next link in the chain
                dep_req = conn.create_dependant_request_frames('POST', '/long', stream_id=current_sid, dependency_stream_id=prev_sid)
                dep_chain_reqs.append(dep_req)

            # The last link in the chain on which all race requests will depend
            end_of_chain_sid = chain_sids[-1]

            # Create and gather the concurrent race requests
            race_reqs = []
            for sid in race_sids:
                race_req = conn.create_dependant_request_frames(this_flow.request.method, this_flow.request.path , sid , headers=this_flow.request.headers,body=this_flow.request.content[:-1])#('POST', '/race', stream_id=sid, dependency_stream_id=end_of_chain_sid)
                race_reqs.append(race_req)

            # First send the requests that create the dependency chain
            conn.send_frames(*dep_chain_reqs)
            # Finally, send the race requests that should get executed concurrently after the chain has completed
            conn.send_frames(*race_reqs)

# Keep the connection open
conn.infinite_read_loop()

addons = [DepReplay()]
