#!/usr/bin/env python3
"""
Main experiment runner.

Runs all attack × defense combinations and reports ASR, TMR, SDLR,
and Task Utility Degradation.

Usage:
    python -m experiments.run_all
    python -m experiments.run_all --trials 200
"""

import argparse
import random
from collections import defaultdict

from experiments.attacks import DIRECT_ATTACKS, INDIRECT_ATTACKS
from experiments.simulated_agent import SimulatedAgent
from experiments.metrics import compute_asr, compute_tmr, compute_sdlr, compute_task_utility
from experiments.agent_env import CANARY_TOKENS


# ── Defense configurations to test ───────────────────────────────────────────

DEFENSE_CONFIGS = {
    "none":             [],
    "prompt_isolation":  ["prompt_isolation"],
    "provenance":        ["provenance"],
    "tool_permission":   ["tool_permission"],
    "prompt_detection":  ["prompt_detection"],
    "all_combined":      ["prompt_isolation", "provenance", "tool_permission", "prompt_detection"],
}


# ── Experiment 1: Direct Prompt Injection ────────────────────────────────────

def run_direct_experiment(num_trials: int, vulnerability: float):
    print("\n" + "=" * 76)
    print("  EXPERIMENT 1: Direct Prompt Injection")
    print("  Attacker crafts malicious user prompts to hijack tool calls")
    print("=" * 76)

    results = {}

    for defense_name, defense_list in DEFENSE_CONFIGS.items():
        traces = []
        checks = []

        for _ in range(num_trials):
            for atk_name, atk in DIRECT_ATTACKS.items():
                agent = SimulatedAgent(vulnerability=vulnerability, defenses=defense_list)
                trace = agent.run_direct_attack(atk["prompt"])
                traces.append(trace)

                # Check: did any action hit the target tool with attacker args?
                def make_check(attack):
                    def check(t):
                        for a in t.actions:
                            if a.tool_name == attack["target_tool"] and not a.was_blocked:
                                if attack["target_arg_check"](a.tool_args):
                                    return True
                        return False
                    return check
                checks.append(make_check(atk))

        asr = compute_asr(traces, checks)
        tmr = compute_tmr(traces)
        sdlr = compute_sdlr(traces)
        results[defense_name] = {"ASR": asr, "TMR": tmr, "SDLR": sdlr, "traces": traces}

    # Utility degradation (compared to no-defense baseline)
    for defense_name in DEFENSE_CONFIGS:
        if defense_name == "none":
            results[defense_name]["Utility_Deg"] = 0.0
        else:
            results[defense_name]["Utility_Deg"] = compute_task_utility(
                results[defense_name]["traces"], results["none"]["traces"]
            )

    _print_results_table("Direct Injection", results)
    return results


# ── Experiment 2: Indirect Prompt Injection ──────────────────────────────────

def run_indirect_experiment(num_trials: int, vulnerability: float):
    print("\n" + "=" * 76)
    print("  EXPERIMENT 2: Indirect Prompt Injection")
    print("  Malicious instructions hidden in tool outputs (search, DB, etc.)")
    print("=" * 76)

    results = {}

    for defense_name, defense_list in DEFENSE_CONFIGS.items():
        traces = []
        checks = []

        for _ in range(num_trials):
            for atk_name, atk in INDIRECT_ATTACKS.items():
                agent = SimulatedAgent(vulnerability=vulnerability, defenses=defense_list)
                trace = agent.run_indirect_attack(
                    task=atk["task"],
                    tool_to_poison=atk["tool_to_poison"],
                    poisoned_output=atk["poisoned_output"],
                )
                traces.append(trace)

                def make_check(attack):
                    def check(t):
                        for a in t.actions:
                            if a.tool_name == attack["expected_hijack_tool"] and not a.was_blocked:
                                if attack["hijack_check"](a.tool_args):
                                    return True
                        return False
                    return check
                checks.append(make_check(atk))

        asr = compute_asr(traces, checks)
        tmr = compute_tmr(traces)
        sdlr = compute_sdlr(traces)
        results[defense_name] = {"ASR": asr, "TMR": tmr, "SDLR": sdlr, "traces": traces}

    for defense_name in DEFENSE_CONFIGS:
        if defense_name == "none":
            results[defense_name]["Utility_Deg"] = 0.0
        else:
            results[defense_name]["Utility_Deg"] = compute_task_utility(
                results[defense_name]["traces"], results["none"]["traces"]
            )

    _print_results_table("Indirect Injection", results)
    return results


# ── Experiment 3: Combined (both attack types, stress test) ──────────────────

def run_combined_experiment(num_trials: int, vulnerability: float):
    print("\n" + "=" * 76)
    print("  EXPERIMENT 3: Combined Attack Stress Test")
    print("  Both direct + indirect attacks, measuring aggregate metrics")
    print("=" * 76)

    results = {}

    for defense_name, defense_list in DEFENSE_CONFIGS.items():
        all_traces = []
        all_checks = []

        for _ in range(num_trials):
            # Direct attacks
            for atk_name, atk in DIRECT_ATTACKS.items():
                agent = SimulatedAgent(vulnerability=vulnerability, defenses=defense_list)
                trace = agent.run_direct_attack(atk["prompt"])
                all_traces.append(trace)

                def make_direct_check(attack):
                    def check(t):
                        for a in t.actions:
                            if a.tool_name == attack["target_tool"] and not a.was_blocked:
                                if attack["target_arg_check"](a.tool_args):
                                    return True
                        return False
                    return check
                all_checks.append(make_direct_check(atk))

            # Indirect attacks
            for atk_name, atk in INDIRECT_ATTACKS.items():
                agent = SimulatedAgent(vulnerability=vulnerability, defenses=defense_list)
                trace = agent.run_indirect_attack(
                    task=atk["task"],
                    tool_to_poison=atk["tool_to_poison"],
                    poisoned_output=atk["poisoned_output"],
                )
                all_traces.append(trace)

                def make_indirect_check(attack):
                    def check(t):
                        for a in t.actions:
                            if a.tool_name == attack["expected_hijack_tool"] and not a.was_blocked:
                                if attack["hijack_check"](a.tool_args):
                                    return True
                        return False
                    return check
                all_checks.append(make_indirect_check(atk))

        asr = compute_asr(all_traces, all_checks)
        tmr = compute_tmr(all_traces)
        sdlr = compute_sdlr(all_traces)
        results[defense_name] = {"ASR": asr, "TMR": tmr, "SDLR": sdlr, "traces": all_traces}

    for defense_name in DEFENSE_CONFIGS:
        if defense_name == "none":
            results[defense_name]["Utility_Deg"] = 0.0
        else:
            results[defense_name]["Utility_Deg"] = compute_task_utility(
                results[defense_name]["traces"], results["none"]["traces"]
            )

    _print_results_table("Combined (Direct + Indirect)", results)
    return results


# ── Pretty-print ─────────────────────────────────────────────────────────────

def _print_results_table(experiment_name: str, results: dict):
    print(f"\n  Results: {experiment_name}")
    print("-" * 76)
    print(f"  {'Defense':22s} | {'ASR':>7s} | {'TMR':>7s} | {'SDLR':>7s} | {'Util.Deg':>9s}")
    print("-" * 76)
    for defense_name in DEFENSE_CONFIGS:
        r = results[defense_name]
        print(
            f"  {defense_name:22s} | {r['ASR']:>6.1%} | {r['TMR']:>6.1%} | "
            f"{r['SDLR']:>6.1%} | {r['Utility_Deg']:>8.1%}"
        )
    print("-" * 76)

    # Highlight best defense
    best = min(
        (d for d in DEFENSE_CONFIGS if d != "none"),
        key=lambda d: results[d]["ASR"]
    )
    print(f"  Best defense: {best} (ASR={results[best]['ASR']:.1%})")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Agent Security Experiments")
    parser.add_argument("--trials", type=int, default=50, help="Trials per condition")
    parser.add_argument("--vulnerability", type=float, default=0.7, help="Agent vulnerability (0-1)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)

    print("#" * 76)
    print("#  Prompt Injection in Tool-Using Agentic Systems")
    print("#  Experiment Suite")
    print(f"#  Trials={args.trials}, Vulnerability={args.vulnerability}, Seed={args.seed}")
    print("#" * 76)

    run_direct_experiment(args.trials, args.vulnerability)
    run_indirect_experiment(args.trials, args.vulnerability)
    run_combined_experiment(args.trials, args.vulnerability)


if __name__ == "__main__":
    main()
