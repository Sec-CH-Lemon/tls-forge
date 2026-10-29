#!/usr/bin/env python3
"""Validate paired H3 evidence with independent ls-qpack; never hide unknown states."""
import argparse
import base64
from collections import Counter
import hashlib
import importlib.metadata
import json
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def integer(data, at=0):
    if at >= len(data):
        raise ValueError('truncated QUIC varint')
    size = 1 << (data[at] >> 6)
    if at + size > len(data):
        raise ValueError('truncated QUIC varint')
    return int.from_bytes(data[at:at + size], 'big') & ((1 << (8 * size - 2)) - 1), at + size


def frames(raw):
    at = 0
    result = []
    while at < len(raw):
        kind, at = integer(raw, at)
        size, at = integer(raw, at)
        if size > 1 << 20 or at + size > len(raw):
            raise ValueError('invalid/truncated HTTP3 frame')
        result.append((kind, raw[at:at + size]))
        at += size
    return result


def pairs(raw):
    result = []
    ids = set()
    at = 0
    while at < len(raw):
        key, at = integer(raw, at)
        value, at = integer(raw, at)
        if key in ids:
            raise ValueError('duplicate SETTINGS identifier')
        ids.add(key)
        result.append((key, value))
    return result


def grease_n(kind):
    if kind < 33 or (kind - 33) % 31:
        raise ValueError('not an RFC9114 GREASE identifier')
    return (kind - 33) // 31


def pearson(counts):
    expected = sum(counts) / len(counts)
    if expected == 0:
        raise ValueError('empty statistical cohort')
    return sum((value - expected) ** 2 / expected for value in counts)


def two_sample(left, right):
    if sum(left) != sum(right):
        raise ValueError('unequal cohort sizes')
    return sum((a - b) ** 2 / (a + b) for a, b in zip(left, right) if a + b)


def observe(connection, profile, scenario):
    # The state is explicit. A half-handshake, resumed session, failed reader
    # or a fourth request cannot silently become a comparable successful case.
    if not connection['tls_complete'] or connection['resumed'] or not connection['closed'] or connection['errors']:
        raise ValueError('incomplete/resumed/error connection')
    if sorted(map(int, connection['requests'])) != [0, 4, 8]:
        raise ValueError('expected exactly3 request streams')
    settings = None
    encoder = b''
    layout = []
    control_shape = []
    grease = None
    for stream_id, encoded in sorted(connection['uni'].items(), key=lambda item: int(item[0])):
        raw = base64.b64decode(encoded, validate=True)
        kind, at = integer(raw)
        layout.append((int(stream_id), kind))
        if kind == 2:
            encoder += raw[at:]
            continue
        if kind != 0 or settings is not None:
            raise ValueError('unexpected/duplicate critical stream')
        control = frames(raw[at:])
        if not control or control[0][0] != 4:
            raise ValueError('SETTINGS must be first on control stream')
        settings = pairs(control[0][1])
        stable = []
        for key, value in settings:
            if key >= 33 and (key - 33) % 31 == 0:
                n = grease_n(key)
                if grease is not None or not scenario['grease']['n_min'] <= n <= scenario['grease']['n_max'] or value > scenario['grease']['value_max']:
                    raise ValueError('invalid/multiple GREASE setting')
                grease = (n, value)
            else:
                stable.append((key, value))
        expected = [(item['id'], item['value']) for item in profile['behavior']['h3.settings']]
        if stable != expected:
            raise ValueError('actual ordered SETTINGS differs from profile')
        control_shape.append(('settings', tuple(stable)))
        grease_frames = 0
        for frame_type, payload in control[1:]:
            if frame_type >= 33 and (frame_type - 33) % 31 == 0:
                n = grease_n(frame_type)
                if n > (1 << profile['behavior']['h3.grease_frame_n_bits']) - 1 or len(payload) not in profile['behavior']['h3.grease_payload_lengths'] or n % 4 != len(payload):
                    raise ValueError('GREASE frame generation relationship differs')
                # Only this source-verified generated field is normalized.
                control_shape.append(('grease',))
                grease_frames += 1
            else:
                control_shape.append(('frame', frame_type, payload.hex()))
        if grease_frames != 1:
            raise ValueError('expected one connection GREASE frame')
    if settings is None or grease is None:
        raise ValueError('missing control SETTINGS/GREASE')
    blocks = []
    for stream_id, encoded in sorted(connection['requests'].items(), key=lambda item: int(item[0])):
        parsed = frames(base64.b64decode(encoded, validate=True))
        if len(parsed) != 1 or parsed[0][0] != 1 or len(parsed[0][1]) < 2:
            raise ValueError('unexpected request frame sequence')
        blocks.append((int(stream_id), parsed[0][1]))
    # C ls-qpack is independent of the product's Go encoder/decoder.
    import pylsqpack
    decoder = pylsqpack.Decoder(65536, 100)
    decoder.feed_encoder(encoder)
    decoded = []
    for stream_id, block in blocks:
        _, fields = decoder.feed_header(stream_id, block)
        decoded.append([(name.decode('utf8'), value.decode('utf8')) for name, value in fields])
    for fields, stimulus in zip(decoded, scenario['requests']):
        values = dict(fields)
        if values.get(':method') != 'GET' or values.get(':scheme') != 'https' or values.get(':path') != stimulus['path']:
            raise ValueError('decoded request differs from actual scenario')
        if stimulus['kind'] == 'fetch' and values.get(scenario['request_header']['name']) != scenario['request_header']['value']:
            raise ValueError('decoded caller header lost')
    used = tuple(block[0] != 0 for _, block in blocks)
    delay = connection['settings_after_requests']
    if any(used[:delay]):
        raise ValueError('dynamic reference before peer advertised capacity')
    # Raw bytes remain exact within a state. No header/order/encoder stream
    # normalization is used: all actors share one actual origin and stimulus.
    shape = (tuple(layout), tuple(control_shape), tuple(block.hex() for _, block in blocks), encoder.hex())
    return {'grease': grease, 'used': used, 'shape': shape, 'fields': decoded}


def analyze(directory, scenario):
    if importlib.metadata.version('pylsqpack') != '0.3.23':
        raise ValueError('independent decoder must match pinned pylsqpack0.3.23')
    saved_scenario = (directory / 'scenario.json').read_bytes()
    profile_raw = (directory / 'candidate-profile.json').read_bytes()
    profile = json.loads(profile_raw)
    identity = json.loads((directory / 'identity.json').read_text())
    if identity['scenario_sha256'] != digest(saved_scenario) or json.loads(saved_scenario) != scenario or scenario['connections_per_cohort'] < 256:
        raise ValueError('scenario identity differs or sample is only a smoke run')
    if identity['profile_sha256'] != digest(profile_raw) or identity['peer_exit_code'] != 0:
        raise ValueError('profile/peer evidence identity differs')
    if profile.get('schema') != 4 or type(profile.get('engine_major')) is not int or profile['engine_major'] != 1:
        raise ValueError('profile engine/schema differs')
    policy = profile['behavior']
    if policy['h3.qpack.encoder_warmup_sections'] != 0 or policy['h3.qpack.encoder_strategy'] != 'insert':
        raise ValueError('profile does not select source-verified first-section rule')
    if (policy['h3.grease_setting_n_min'], policy['h3.grease_setting_n_max'], policy['h3.grease_setting_nonzero']) != (0, 4294967295, False):
        raise ValueError('profile GREASE source range differs')
    raw = (directory / 'observations.json').read_bytes()
    if identity['observation_sha256'] != digest(raw):
        raise ValueError('original observation hash differs')
    connections = json.loads(raw)['connections']
    groups = json.loads((directory / 'campaign.json').read_text())
    if len(groups) != 12 or identity['complete_cohorts'] != 12:
        raise ValueError('incomplete independent cohorts')
    actual = [observe(connection, profile, scenario) for connection in connections]
    result = {'accepted': False, 'normalizations': ['GREASE SETTINGS identifier/value: validate uint32 range, retain originals and statistical bins; no uniqueness requirement', 'GREASE frame type/payload: validate32bitN, Nmod4=length and JSON lengths; retain originals', 'QPACK/header/control bytes: no normalization; compare within explicit peer-SETTINGS state; actor scheduling rates are not an equivalence verdict'], 'groups': [], 'negative_controls': {}, 'scope': scenario['scope'], 'oracle': {'name':'pylsqpack', 'version':'0.3.23'}}
    references = set()
    for group in groups:
        if group['actor'] == 'chrome':
            references.update(item['shape'] for item in actual[group['first_connection'] - 1:group['last_connection']])
    bins_by_actor = {}
    seen = set()
    for group in groups:
        first, last = group['first_connection'] - 1, group['last_connection']
        chosen = actual[first:last]
        count = scenario['connections_per_cohort'] if group['role'] == 'natural' else scenario['controlled_connections_per_cohort']
        if group['exit_code'] or len(chosen) != count or group['samples'] != count:
            raise ValueError('incomplete predeclared sample count')
        for index in range(first, last):
            if index in seen:
                raise ValueError('overlapping cohort evidence')
            seen.add(index)
        if group['actor'] == 'client' and any(item['shape'] not in references for item in chosen):
            raise ValueError('unknown product QPACK/control state; not normalized away')
        summary = {**group, 'qpack_states': dict(Counter(''.join('D' if bit else 'S' for bit in item['used']) for item in chosen))}
        if group['role'] == 'natural':
            bins = [[0] * scenario['grease']['bins'] for _ in range(2)]
            for item in chosen:
                for part in range(2):
                    bins[part][item['grease'][part] >> 28] += 1
            scores = list(map(pearson, bins))
            if any(score > scenario['grease']['pearson_limit'] for score in scores):
                raise ValueError('GREASE predeclared cohort statistic rejected')
            summary.update({'grease_bins':bins, 'pearson':scores})
            bins_by_actor[group['actor'], group['cohort']] = bins
        result['groups'].append(summary)
    if len(seen) != len(connections):
        raise ValueError('unassigned connection evidence')
    result['cross_actor_statistics'] = []
    for cohort in [1, 2]:
        scores = [two_sample(a, b) for a, b in zip(bins_by_actor['chrome', cohort], bins_by_actor['client', cohort])]
        if any(score > scenario['grease']['pearson_limit'] for score in scores):
            raise ValueError('GREASE browser/client two-sample statistic rejected')
        result['cross_actor_statistics'].append(scores)
    # Distinct actual states must exist, rather than accepting a static-only
    # peer or only comparing decoded fields while omitting QPACK bytes.
    states = {item['used'] for item in actual[:groups[1]['last_connection']]}
    if (False, True, True) not in states and (True, True, True) not in states:
        raise ValueError('native browser dynamic QPACK not observed')
    frozen = [scenario['connections_per_cohort']] + [0] * 15
    if pearson(frozen) <= scenario['grease']['pearson_limit']:
        raise ValueError('frozen-draw negative control did not reject')
    result['negative_controls']['transport_frozen_draw'] = 'rejected by unchanged statistic'
    # Use an actually dynamic stream for the independent decoder corruption
    # control. An empty/table-free test would fail before reaching the defect.
    dynamic_connection = next(connection for connection, item in zip(connections, actual) if any(item['used']))
    broken = json.loads(json.dumps(dynamic_connection))
    for stream_id, encoded in broken['uni'].items():
        data = base64.b64decode(encoded)
        kind, at = integer(data)
        if kind == 2:
            broken['uni'][stream_id] = base64.b64encode(data[:at]).decode()
    try:
        observe(broken, profile, scenario)
    except Exception as error:
        if type(error).__module__.split('.')[0] not in ['pylsqpack']:
            raise
        result['negative_controls']['missing_encoder_instructions'] = type(error).__name__
    else:
        raise ValueError('independent QPACK negative control did not reject')
    result['accepted'] = True
    result['connections'] = len(connections)
    result['requests'] = len(connections) * 3
    result['original_sha256'] = digest(raw)
    result['limitations'] = 'Finite cold/reuse sequence, owned peer and process trust. No resumed/0RTT, blocked-table/error-policy/platform-timer/WAN/TCP-kernel or complete browser-indistinguishability verdict. QPACK first-section state proportions are recorded, not asserted equal under different actor scheduling.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--scenario', type=Path, default=Path('scripts/a8-h3-scenario.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    scenario = json.loads(args.scenario.read_text())
    result = analyze(args.directory, scenario)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'accepted': result['accepted'], 'connections': result['connections'], 'requests': result['requests']}))


if __name__ == '__main__':
    main()
