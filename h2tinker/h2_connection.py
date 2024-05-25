import time
import sys
import typing as T
from abc import ABC

import scapy.contrib.http2 as h2
from scapy.compat import hex_bytes
from scapy.data import MTU

from h2tinker import log
from h2tinker.assrt import assert_error
from h2tinker.frames import is_frame_type, has_ack_set, create_settings_frame

import logging
import contextlib

class OutputLogger:
    def __init__(self, logger, level="INFO"):
        self.logger = logger
        self.name = self.logger.name
        self.level = getattr(logging, level)

    def write(self, msg):
        if msg and not msg.isspace():
            self.logger.log(self.level, msg)

    def flush(self): pass


class H2Connection(ABC):
    """
    Base class for HTTP/2 connections.
    """

    PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')

    def __init__( self, logger ):
        self.host = None
        self.port = None
        self.sock = None
        self.is_setup_completed = False
        self.logger = logger
        self.output_logger = OutputLogger(logger)
        sys.stdout = self.output_logger

    def _check_setup_completed(self):
        assert_error(self.is_setup_completed, 'Connection setup has not been completed, call setup(...) '
                                              'before operating with the connection')

    def setup(self, host: str, port: int):
        assert_error(not self.is_setup_completed, 'Connection setup has already been completed with '
                                                  '{}:{}', self.host, self.port)

    def create_request_frames(self, method: str, path: str, stream_id: int,
                              headers: tuple[tuple[str, str] , ...] = None,
                              body: T.Optional[bytes] = None) -> h2.H2Seq:
        """
        Create HTTP/2 frames representing a HTTP request.
        :param method: HTTP request method, e.g. GET
        :param path: request path, e.g. /example/path
        :param stream_id: stream ID to use for this request, e.g. 1
        :param headers: request headers
        :param body: request body
        :return: frame sequence consisting of a single HEADERS frame, potentially followed by CONTINUATION and DATA frames
        """
        header_table = h2.HPackHdrTable()
        req_str = (':method {}\n'
                   ':path {}\n'
                   ':scheme http\n'
                   ':authority {}:{}\n').format(method, path, self.host, self.port)
        self.logger.info(f"[h2tinker.create_request_frames] req_str before headers: {req_str}")

        if headers is not None:
            req_str += '\n'.join(map(lambda e: '{}: {}'.format(e[0], e[1]), headers))
        self.logger.info(f"[h2tinker.create_request_frames] req_str after headers: {req_str}")

        # noinspection PyTypeChecker
        return header_table.parse_txt_hdrs(
            bytes(req_str.strip(), 'UTF-8'),
            stream_id=stream_id,
            body=body
        )

    def create_dependant_request_frames(self, method: str, path: str, stream_id: int,
                                        dependency_stream_id: int = 0,
                                        dependency_weight: int = 0,
                                        dependency_is_exclusive: bool = False,
                                        headers: tuple[tuple[bytes, bytes], ...] = None,
                                        body: T.Optional[bytes] = None) -> h2.H2Seq:
        """
        Create HTTP/2 frames representing a HTTP request that depends on another request (stream).
        :param method: HTTP request method, e.g. GET
        :param path: request path, e.g. /example/path
        :param stream_id: stream ID to use for this request, e.g. 1
        :param dependency_stream_id: ID of the stream that this request (stream) will depend upon
        :param dependency_weight: weight of the dependency
        :param dependency_is_exclusive: whether the dependency is exclusive
        :param headers: request headers
        :param body: request body
        :return: frame sequence consisting of a single HEADERS frame, potentially followed by CONTINUATION and DATA frames
        """
        req_frameseq = self.create_request_frames(method, path, stream_id, headers, body)
        dep_req_frames = []
        for f in req_frameseq.frames:
            if is_frame_type(f, h2.H2HeadersFrame):
                pri_hdr_frame = h2.H2PriorityHeadersFrame()
                pri_hdr_frame.stream_dependency = dependency_stream_id
                pri_hdr_frame.weight = dependency_weight
                pri_hdr_frame.exclusive = 1 if dependency_is_exclusive else 0
                pri_hdr_frame.hdrs = f.hdrs
                dep_req_frames.append(
                    h2.H2Frame(stream_id=f.stream_id, flags=f.flags | {'+'}) / pri_hdr_frame
                )
            else:
                dep_req_frames.append(f)

        req_frameseq.frames = dep_req_frames
        return req_frameseq

    def infinite_read_loop(self, print_frames: bool = True):
        """
        Start an infinite loop that reads and possibly prints received frames.
        :param print_frames: whether to print received frames
        """
        self._check_setup_completed()
        self.logger.info("[h2tinker/h2_connection.infinite_read_loop] 10 second timed receive loop starting...")
        timeout = time.time() + 10
        while True:
            if time.time() > timeout:
                break
            frames = self._recv_frames()
            if print_frames:
                for f in frames:
                    self.logger.info("Read frame:")
                    f.show()

    def send_frames(self, *frames: h2.H2Frame):
        """
        Send frames on this connection.
        :param frames: 1 or more frames to send
        """
        self._check_setup_completed()
        self._send_frames(*frames)

    def recv_frames(self) -> T.List[h2.H2Frame]:
        """
        Synchronously receive frames. Block if there aren't any frames to read.
        :return: list of received frames
        """
        self._check_setup_completed()
        return self._recv_frames()

    def _setup_wait_loop(self):
        server_has_acked_settings = False
        we_have_acked_settings = False
        while not server_has_acked_settings or not we_have_acked_settings:
            frames = self._recv_frames()
            for f in frames:
                self.logger.info(f"[h2tinker/h2_connection.py info] _setup_wait_loop type(f): {type(f)}")
                try:
                    if is_frame_type(f, h2.H2SettingsFrame):
                        self.logger.info(f"[h2tinker/h2_connection.py info] _setup_wait_loop: is H2SettingsFrame, true")
                        if has_ack_set(f):
                            self.logger.info("Server acked our settings")
                            server_has_acked_settings = True
                        else:
                            self.logger.info("Got server settings, acking")
                            self._ack_settings()
                            we_have_acked_settings = True
                except ValueError:
                        self.logger.info(f"[h2tinker/h2_connection.py info] ValueError while attempting to check frame type - possibly raw packet")


    def _ack_settings(self):
        self._send_frames(create_settings_frame(is_ack=True))
        self.logger.info("Acked server settings")

    def _send_initial_settings(self):
        settings = [
            h2.H2Setting(id=h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
            h2.H2Setting(id=h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=2_147_483_647),
            h2.H2Setting(id=h2.H2Setting.SETTINGS_MAX_CONCURRENT_STREAMS, value=1000)
        ]
        self._send_frames(create_settings_frame(settings))
        self.logger.info("Sent settings")

    def _send_frames(self, *frames: h2.H2Frame):
        b = bytes()
        for f in frames:
            b += bytes(f)
        self._send(b)

    def _send_preface(self):
        self._send(self.PREFACE)

    def _send(self, bytez):
        self.sock.send(bytez)

    def _recv_frames(self) -> T.List[h2.H2Frame]:
        chunk = self._recv()
        return h2.H2Seq(chunk).frames

    def _recv(self):
        while True:
            try:
                return self.sock.recv(MTU)
            except AssertionError:
                # Frame parsing failed on current data, try again in 100 ms
                time.sleep(0.1)
