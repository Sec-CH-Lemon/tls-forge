#!/usr/bin/env python3
"""Independently authenticate and reassemble private H3 UDP evidence with TShark."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import xml.etree.ElementTree as ET


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksum(raw):
    value = sum(struct.unpack('!10H', raw))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def envelope(source, destination, omit_client_short=False):
    """Synthetic IPv4/UDP headers only; original UDP payloads remain exact."""
    packets = 0
    server_port = None
    with destination.open('xb') as output, source.open() as records:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for line in records:
            record = json.loads(line)
            local = record['local'].rsplit(':', 1)
            remote = record['remote'].rsplit(':', 1)
            port = int(local[1])
            if server_port is not None and port != server_port:
                raise ValueError('server port changed inside campaign')
            server_port = port
            src, dst = (remote, local) if record['direction'] == 'client' else (local, remote)
            if record['direction'] not in ['client', 'server']:
                raise ValueError('unknown packet direction')
            data = base64.b64decode(record['data'], validate=True)
            if omit_client_short and record['direction'] == 'client' and data and not data[0] & 0x80:
                continue
            udp = struct.pack('!HHHH', int(src[1]), int(dst[1]), 8 + len(data), 0) + data
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                                 socket.inet_aton(src[0]), socket.inet_aton(dst[0]))
            packet = header[:10] + struct.pack('!H', checksum(header)) + header[12:] + udp
            time_ns = record['time_ns']
            output.write(struct.pack('<IIII', time_ns // 10**9, time_ns % 10**9 // 1000,
                                     len(packet), len(packet)) + packet)
            packets += 1
    return server_port, packets


def decode(tshark, pcap, keys, port, out):
    pdml = out.with_suffix('.pdml')
    with pdml.open('xb') as output, out.with_suffix('.stderr').open('xb') as errors:
        subprocess.run([str(tshark), '-n', '-r', str(pcap), '-o', 'tls.keylog_file:' + str(keys),
                        '-d', f'udp.port=={port},quic', '--disable-protocol', 'http3',
                        '-Y', 'quic', '-T', 'pdml'], stdout=output, stderr=errors, check=True)
    streams = {}
    for _, packet in ET.iterparse(pdml, events=['end']):
        if packet.tag != 'packet':
            continue
        destination = packet.find(".//field[@name='udp.dstport']")
        connection = packet.find(".//field[@name='quic.connection.number']")
        if destination is not None and int(destination.attrib['show']) == port and connection is not None:
            number = int(connection.attrib['show'])
            for frame in packet.findall(".//field[@name='quic.frame']"):
                data = frame.find("./field[@name='quic.stream_data']")
                if data is None:
                    continue
                stream_id = int(frame.find("./field[@name='quic.stream.stream_id']").attrib['show'])
                offset = frame.find("./field[@name='quic.stream.offset']")
                start = int(offset.attrib['show']) if offset is not None else 0
                value = bytes.fromhex(data.attrib['value'])
                target = streams.setdefault(number, {}).setdefault(stream_id, {})
                for index, byte in enumerate(value, start):
                    if index in target and target[index] != byte:
                        raise ValueError('conflicting independently authenticated retransmission')
                    target[index] = byte
        packet.clear()
    return streams


def compare(streams, observations):
    expected = observations['connections']
    if len(streams) != len(expected):
        raise ValueError('independently decoded connection cardinality differs')
    for number, connection in enumerate(expected):
        actual = streams.get(number, {})
        desired = {int(key): base64.b64decode(value, validate=True)
                   for key, value in {**connection['uni'], **connection['requests']}.items()}
        if set(actual) != set(desired):
            raise ValueError('independently decoded stream cardinality differs')
        for stream_id, raw in desired.items():
            recovered = actual[stream_id]
            if set(recovered) != set(range(len(raw))) or bytes(recovered[i] for i in range(len(raw))) != raw:
                raise ValueError('independently decrypted stream bytes differ')
    return sum(len(value) for value in streams.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--tshark', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    version = subprocess.check_output([str(args.tshark), '--version'], text=True).splitlines()[0]
    if '4.6.9' not in version:
        raise ValueError('decoder must match pinned TShark4.6.9')
    source = args.directory / 'packets.jsonl'
    keys = args.directory / 'keys.log'
    observation_file = args.directory / 'observations.json'
    observations = json.loads(observation_file.read_text())
    pcap = args.out / 'synthetic-envelope.pcap'
    port, packets = envelope(source, pcap)
    streams = decode(args.tshark, pcap, keys, port, args.out / 'decoded')
    count = compare(streams, observations)
    empty_keys = args.out / 'empty-keys.log'
    empty_keys.write_bytes(b'')
    controls = {}
    removed = args.out / 'removed-client-application.pcap'
    envelope(source, removed, omit_client_short=True)
    for name, control_pcap, control_keys in [('missing-keys', pcap, empty_keys), ('missing-client-application', removed, keys)]:
        result = decode(args.tshark, control_pcap, control_keys, port, args.out / name)
        try:
            compare(result, observations)
        except ValueError as error:
            controls[name] = str(error)
        else:
            raise ValueError('independent packet negative control was accepted')
    result = {'accepted': True, 'decoder': version, 'decoder_sha256': sha(args.tshark),
              'source_sha256': sha(source), 'observation_sha256': sha(observation_file),
              'pcap_sha256': sha(pcap), 'connections': len(streams), 'streams': count,
              'packets': packets, 'negative_controls': controls,
              'scope': 'Exact original UDP payloads with synthetic IPv4/UDP envelope for independent authenticated QUIC decoding. Not a host IP/ECN/GSO/kernel capture. Stream bytes must equal the separately retained observer output, including overlap and gap checks.'}
    (args.out / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['accepted', 'connections', 'streams', 'packets']}))


if __name__ == '__main__':
    main()
