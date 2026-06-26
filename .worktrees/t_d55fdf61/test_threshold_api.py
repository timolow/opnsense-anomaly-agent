import urllib.request, json, sys

sys.path.insert(0, '/app')

# Test feedback endpoint
data = json.dumps({
    "anomaly_id": 1,
    "label": "false_positive",
    "reason": "legitimate traffic spike during backup",
    "user_id": "test"
}).encode()

req = urllib.request.Request(
    'http://localhost:8766/api/threshold-feedback',
    data=data,
    headers={'Content-Type': 'application/json'},
    method='POST'
)

try:
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    print('FEEDBACK RESULT:', json.dumps(result, indent=2))
except Exception as e:
    print(f'Feedback error: {e}')

# Test manual tune endpoint
req2 = urllib.request.Request(
    'http://localhost:8766/api/threshold-tune',
    data=b'{}',
    headers={'Content-Type': 'application/json'},
    method='POST'
)

try:
    resp = urllib.request.urlopen(req2)
    result = json.loads(resp.read())
    print('TUNE RESULT:', json.dumps(result, indent=2)[:500])
except Exception as e:
    print(f'Tune error: {e}')

# Test threshold-set endpoint
data3 = json.dumps({
    "threshold_type": "volume_zscore",
    "value": 2.8
}).encode()

req3 = urllib.request.Request(
    'http://localhost:8766/api/threshold-set',
    data=data3,
    headers={'Content-Type': 'application/json'},
    method='POST'
)

try:
    resp = urllib.request.urlopen(req3)
    result = json.loads(resp.read())
    print('SET RESULT:', json.dumps(result, indent=2))
except Exception as e:
    print(f'Set error: {e}')