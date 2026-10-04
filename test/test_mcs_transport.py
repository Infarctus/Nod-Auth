"""Scripted MCS wire tests; no real credentials or external connections."""
import io
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from app.mcs import APP, McsListener, pb_fields, pb_int, pb_str, varint


def message(field, body):
    return varint((field << 3) | 2) + varint(len(body)) + body


def frame(tag, body=b''):
    return bytes([tag]) + varint(len(body)) + body


class McsWireTests(unittest.TestCase):
    def run_wire(self, wire, interrupt=False):
        listener = McsListener(123, 456)
        pending = bytearray(wire)
        sock = Mock()
        timeout_next = False

        def recv(size):
            nonlocal timeout_next
            if timeout_next:
                timeout_next = False
                raise socket.timeout()
            if not pending:
                return b''
            # Force fragmentation even inside protobuf varints and bodies.
            value = bytes(pending[:1])
            del pending[:1]
            timeout_next = interrupt
            return value

        sock.recv.side_effect = recv
        context = Mock()
        context.wrap_socket.return_value = sock
        output = io.StringIO()
        with patch('app.mcs.socket.create_connection', return_value=sock), \
                patch('app.mcs.ssl.create_default_context', return_value=context), \
                redirect_stdout(output):
            listener.run()
        sock.close.assert_called_once()
        return listener, sock, output.getvalue()

    def test_fragmented_login_heartbeat_and_push_are_acknowledged(self):
        appdata = message(7, pb_str(1, 'guid') + pb_str(2, 'fake-guid'))
        data = pb_str(3, 'sender') + pb_str(5, APP) + appdata + pb_int(24, 1)
        listener, sock, output = self.run_wire(
            b'\x29' + frame(3, pb_str(1, 'ok')) + frame(0) + frame(8, data), True)
        self.assertIn('LOGIN OK', output)
        self.assertEqual(listener.pushes, [{'category': APP, 'app_data': {'guid': 'fake-guid'}}])
        self.assertFalse(listener.ready.is_set())  # Cleared when disconnected.
        sent = [call.args[0] for call in sock.sendall.call_args_list]
        self.assertEqual(sent[2], frame(1, pb_int(2, 2)))
        self.assertEqual(sent[3][0], 7)
        fields = pb_fields(sent[3][2:])
        self.assertIn((2, 0, 1), fields)  # IQ SET
        self.assertIn((3, 2, b''), fields)
        self.assertIn((10, 0, 3), fields)  # login + ping + push
        extension = next(v for f, w, v in fields if f == 7)
        self.assertEqual(pb_fields(extension), [(1, 0, 13), (2, 2, b'')])

    def test_rejected_login_is_not_reported_as_success(self):
        error = message(3, pb_int(1, 401) + pb_str(2, 'secret error text'))
        listener, sock, output = self.run_wire(b'\x29' + frame(3, pb_str(1, '') + error))
        self.assertIn('LOGIN FAILED code=401', output)
        self.assertNotIn('LOGIN OK', output)
        self.assertNotIn('secret error text', output)
        self.assertFalse(listener.ready.is_set())
        self.assertFalse(listener.pushes)

    def test_zero_login_error_code_is_success(self):
        _, _, output = self.run_wire(b'\x29' + frame(3, message(3, pb_int(1, 0))))
        self.assertIn('LOGIN OK', output)

    def test_every_push_in_long_session_is_acknowledged(self):
        data = pb_str(3, 'sender') + pb_str(5, APP)
        listener, sock, _ = self.run_wire(b'\x29' + frame(3) + frame(8, data) * 25)
        acknowledgments = [c.args[0] for c in sock.sendall.call_args_list if c.args[0][0] == 7]
        self.assertEqual(len(listener.pushes), 25)
        self.assertEqual(len(acknowledgments), 25)
        self.assertIn((10, 0, 26), pb_fields(acknowledgments[-1][2:]))

    def test_other_app_is_acknowledged_but_not_delivered(self):
        listener, sock, _ = self.run_wire(b'\x29' + frame(3) + frame(8, pb_str(5, 'other.app')))
        self.assertFalse(listener.pushes)
        self.assertEqual(sock.sendall.call_args.args[0][0], 7)

    def test_truncated_frame_does_not_deliver_partial_push(self):
        listener, _, _ = self.run_wire(b'\x29' + frame(3) + b'\x08\x10short')
        self.assertFalse(listener.pushes)

    def test_invalid_frame_lengths_disconnect(self):
        for length in (b'\x80' * 5, varint(1024 * 1024 + 1)):
            with self.subTest(length=length):
                listener, _, output = self.run_wire(b'\x29' + frame(3) + b'\x08' + length)
                self.assertFalse(listener.pushes)
                self.assertIn('connection lost', output)

    def test_idle_heartbeat_includes_incoming_stream_counter(self):
        listener = McsListener(123, 456)
        listener.stream_id = 12
        sock = Mock()
        sock.recv.side_effect = [socket.timeout(), b'\x01']
        with patch('app.mcs.time.monotonic', side_effect=[0, 46]):
            self.assertEqual(listener._read_exact(sock, 1), b'\x01')
        sock.sendall.assert_called_once_with(frame(0, pb_int(2, 12)))


if __name__ == '__main__':
    unittest.main()
