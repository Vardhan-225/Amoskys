"""CLI entry point for NetworkSentinel agent."""

from amoskys.agents.shared.network_sentinel.agent import NetworkSentinelAgent


def main():
    import argparse
    import logging

    parser = argparse.ArgumentParser(description="AMOSKYS Network Sentinel")
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    agent = NetworkSentinelAgent(collection_interval=args.interval)
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        agent.shutdown()


if __name__ == "__main__":
    main()
