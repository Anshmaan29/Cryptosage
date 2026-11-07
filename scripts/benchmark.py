"""Real full protocol and KEM comparison, without inferring network latency."""
import argparse
from benchmarks.runner import run
from benchmarks.protocol_adapter import factory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trials',type=int,default=30)
    p.add_argument('--output',default='reports/benchmarks')
    a = p.parse_args()
    callback, directory = factory()
    try:
        report = run(a.trials,a.output,handshake_factory=callback)
    finally:
        directory.cleanup()
    for item in report['algorithms']:
        print(item['name'],item['status'],
              item.get('statistics',{}).get('handshake_ms',{}).get('mean','unavailable'))
    print('Saved real measurements and graphs to',a.output)


if __name__ == '__main__':
    main()
