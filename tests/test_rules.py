import sys, pathlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from engine import extract_signals, merge_findings, parse_json

def test_assessment():
    path=pathlib.Path(__file__).resolve().parents[1]/'sample'/'assessment.log'
    findings,dupes=extract_signals(path)
    assert any('brute force' in f['type'].lower() and f['ip']=='203.0.113.44' for f in findings)
    assert any('sql' in f['type'].lower() and f['ip']=='203.0.113.72' for f in findings)
    assert any('scanning' in f['type'].lower() for f in findings)
    assert 223 in dupes

def test_json():
    assert parse_json('```json\n{"findings":[]}\n```')==[]
    assert parse_json('bad response')==[]

if __name__=='__main__':
    test_assessment();test_json();print('Tests passed')
