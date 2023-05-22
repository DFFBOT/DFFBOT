#!/usr/bin/env python3
import angr
import networkx
import os
import sys
import itertools
import math


def find_distance_basic_blocks(proj, targets):
    """Find the binary address of the targets and return it as list.

    targets: List of ('source_file', line) tuples. E.g. [('main.c', 9)]
    """
    possible_comp_dirs = []
    for comp_unit in proj.loader.main_object.compilation_units:
        if comp_unit.comp_dir.endswith("build"):
            compilation_dir = os.path.abspath(
                os.path.join(comp_unit.comp_dir, "..")
            )
        else:
            compilation_dir = os.path.abspath(comp_unit.comp_dir)
        possible_comp_dirs.append(compilation_dir)

    target_distances = dict()
    for target in targets:
        key = f"{target[0]}:{target[1]}"
        target_distances[key] = target[2]

    results = []
    addr_mapping = proj.loader.main_object.addr_to_line
    for addr, mapping in addr_mapping.items():
        source_file_mapping, line = list(mapping)[0]

        for comp_dir in possible_comp_dirs:
            if comp_dir in source_file_mapping:
                source_file_mapping = os.path.relpath(source_file_mapping, comp_dir)
                break

        """
        # In case for files with (../main.c, ../utils.c, ...)
        if source_file_mapping.startswith("../"):
            source_file_mapping = source_file_mapping[3:]
        """
        if "/" in source_file_mapping:
            source_file_mapping = source_file_mapping.rsplit("/", 1)[1]

        contains_str = f"{source_file_mapping}:{line}"
        value = target_distances.pop(contains_str, None)
        if value:
            results.append((addr, value))

    target_distances_len = len(target_distances)
    if target_distances_len > 0:
        print(
            f"Warning, not all distances was found in the binary! (Found: {len(targets) - target_distances_len} / {len(targets)})"
        )
    return results


def find_bb_targets_from_addrs(proj, cfg, targets):
    results = {}
    for target_addr, distance in targets:
        bb_node = cfg.get_any_node(target_addr, anyaddr=True)

        previous_distance = results.get(bb_node.addr, 0)
        if previous_distance < distance:
            results[bb_node.addr] = distance

    list_result = [
        (bb_node_addr, distance_val)
        for bb_node_addr, distance_val in results.items()
    ]
    return list_result




def main():
    if len(sys.argv) != 4:
        print("Not enough arguments!")
        usage_str = f"{sys.argv[0]} [Binary] [distance.cfg.txt] [Output]"
        print(usage_str)
        exit()

    distance_cfg_file = sys.argv[2]
    targets = []
    with open(distance_cfg_file, "r") as file_obj:
        bbtargets_reader = file_obj.readlines()
        for bbtarget_line in bbtargets_reader:
            distance_split = bbtarget_line.split(",")
            if len(distance_split) != 2:
                error_str = f"Wrong format of line: {bbtarget_line}"
                raise ValueError(error_str)
            
            bbtarget, distance = distance_split
            splitted_bbtarget = bbtarget.split(":")
            if len(splitted_bbtarget) != 2:
                error_str = f"Wrong format of BBtarget: {bbtarget_line}"
                raise ValueError(error_str)
            
            source_target, line = splitted_bbtarget
            line = int(line)
            distance = float(distance)
            targets.append(
                (source_target, line, distance)
            )

    if not targets:
        print("The distance file has no targets!")
        exit(0)

    binary_path = sys.argv[1]

    # "Entry Point" - Depending on the binary :-/
    #proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': 0, "force_rebase": True})
    proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False)

    #cfg = proj.analyses.CFGEmulated(
    #    keep_state=True,
    #    # Should be incrased if targets not found!
    #    max_iterations=10
    #)
    cfg = proj.analyses.CFGFast()

    target_addrs = find_distance_basic_blocks(proj, targets)
    target_bb_blocks = find_bb_targets_from_addrs(proj, cfg, target_addrs)
    target_bb_blocks = sorted(
        target_bb_blocks,
        key=lambda x: x[0]
    )

    # Store the results
    destination_path = sys.argv[3]
    with open(destination_path, "w") as file_obj:
        content = "\n".join(
            f"{hex(node_addr)},{bb_distance}"
            for node_addr, bb_distance in target_bb_blocks
        )
        file_obj.write(content)


if __name__ == "__main__":
    main()
