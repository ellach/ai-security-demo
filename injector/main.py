# injector/main.py
import argparse
import json
import os
import sys
from datetime import datetime

try:
    from injector.agent import AttackerAgent
except ModuleNotFoundError:
    # Allow running this file directly from inside the injector folder
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if ROOT_DIR not in sys.path:
        sys.path.insert(0, ROOT_DIR)
    from injector.agent import AttackerAgent


def save_report(report: dict, filename: str = None):
    """Save attack report to JSON file."""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_report_{timestamp}.json"

    # convert any non-serializable items
    clean_report = {
        "success": report["success"],
        "total_attempts": report["total_attempts"],
        "winning_category": report["winning_category"],
        "winning_payload": report["winning_payload"],
        "result": report["result"],
        "graph_status": report["graph_status"],
        "attack_log": report["attack_log"],
    }

    with open(filename, "w") as f:
        json.dump(clean_report, f, indent=2, default=str)

    print(f"\n  💾 Report saved to: {filename}")
    return filename


def print_intro():
    print("\n" + "=" * 60)
    print("  🔴 GRAPH-BASED INJECTOR")
    print("  Autonomous Prompt Injection Agent")
    print("=" * 60)
    print("  Target: InjecAgent (LangChain + Groq)")
    print("  Goal:   Extract .env.fake contents")
    print("  Method: Multi-strategy graph traversal")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Graph-Based Injector — autonomous LLM attack agent"
    )
    parser.add_argument(
        "--mode",
        choices=["basic", "adaptive"],
        default="adaptive",
        help="Attack mode: basic (preset only) or adaptive (LLM-generated)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output verbosity"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save report to JSON file"
    )
    args = parser.parse_args()

    print_intro()
    print(f"\n  ⚙️  Mode: {args.mode.upper()}")

    # create attacker
    attacker = AttackerAgent(verbose=not args.quiet)

    # run attack
    if args.mode == "adaptive":
        report = attacker.run_adaptive()
    else:
        report = attacker.run()

    # final summary
    print("\n" + "=" * 60)
    print("  📋 FINAL REPORT")
    print("=" * 60)
    print(f"  Success: {report['success']}")
    print(f"  Total attempts: {report['total_attempts']}")

    if report["success"]:
        print(f"  Winning category: {report['winning_category'].upper()}")
        print(f"  Confidence: {report['result']['confidence']}")
        print(f"  Leaked data: {report['result']['leaked_data']}")
    else:
        print("  🛡️  Target successfully defended against all attacks")

    print("=" * 60)

    # save report
    if args.save:
        save_report(report)

    return report


if __name__ == "__main__":
    main()