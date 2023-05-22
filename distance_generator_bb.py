#!/usr/bin/env python3
import angr
import networkx
import os
import sys
import itertools
import math


def find_target_basic_blocks(proj, targets):
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

    target_distances = set()
    for target in targets:
        key = f"{target[0]}:{target[1]}"
        target_distances.add(key)

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
        is_target_in_set = (contains_str in target_distances)
        if is_target_in_set:
            results.append(addr)
            target_distances.remove(contains_str)

    target_distances_len = len(target_distances)
    if target_distances_len > 0:
        print(
            f"Warning, not all distances was found in the binary! (Amount: {target_distances_len})"
        )
    return results


def find_start_node(cfg):
    """Find the main() function or return the start of the binary."""
    entry_addr = cfg.project.entry
    entry_node = cfg.get_any_node(entry_addr)

    current_node = entry_node
    if current_node.name != "_start" or len(current_node.successors) != 1:
        return entry_node
    current_node = current_node.successors[0]

    if current_node.name != "__libc_start_main" or len(current_node.successors) != 1:
        return entry_node

    current_node = current_node.successors[0]
    if current_node.name == "main":
        return current_node
    return entry_node


def calculate_distance_from_bb_node(cfg, bb_node, targets):
    # Check if bb_node is in the targets (m in T_b)
    for target_node in targets:
        # Distance = 0 if the nodes are the same
        if bb_node == target_node:
            return 0.0
    
    # Use basic block distance
    distance = 0.0
    for target in targets:
        target_bb_path_length = math.inf
        try:
            target_bb_path_length = networkx.shortest_path_length(
                cfg.graph, source=bb_node, target=target_node
            )
            target_bb_path_length = 1 / float(target_bb_path_length)
        except networkx.NetworkXNoPath:
            continue

        distance += target_bb_path_length
    
    if distance == 0.0:
        return math.inf
    return 1 / distance


def calculate_distance(cfg, targets):
    entry_node = find_start_node(cfg)
    results = []
    reduced_bb_graph = networkx.descendants(cfg.graph, entry_node)
    for bb_node in reduced_bb_graph:       
        # Check if the BB node is an "extern node" or "PathTerminator" (end of an BB block)
        if not bb_node.name or bb_node.name == "PathTerminator":
            continue
        # Check if the BB block belongs to a linked target
        bb_node_symbol = cfg.project.loader.find_object_containing(bb_node.addr)
        if bb_node_symbol != cfg.project.loader.main_object:
            continue

        bb_distance = calculate_distance_from_bb_node(cfg, bb_node, targets)
        if bb_distance != math.inf and bb_distance > 0.0:
            results.append((bb_node, bb_distance))
    return results


def main():
    if len(sys.argv) != 4:
        print("Not enough arguments!")
        usage_str = f"{sys.argv[0]} [Binary] [BBtargets.txt] [Output]"
        print(usage_str)
        exit()

    bbtargets_file = sys.argv[2]
    targets = []
    with open(bbtargets_file, "r") as file_obj:
        bbtargets_reader = file_obj.readlines()
        for bbtarget_line in bbtargets_reader:
            splitted_bbtarget = bbtarget_line.split(":")
            if len(splitted_bbtarget) != 2:
                error_str = f"Wrong format of BBtarget: {bbtarget_line}"
                raise ValueError(error_str)
            
            bbtarget, line = splitted_bbtarget
            line = int(line)
            targets.append(
                (bbtarget, line)
            )

    if not targets:
        print("The bbtargets file has no targets!")
        exit(0)


    binary_path = sys.argv[1]
    # "Entry Point" - Depending on the binary :-/
    #proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': 0, "force_rebase": True})
    proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False)
    
    #import joblib
    #proj, cfg = joblib.load("cfg_fast.joblib")

    target_addrs = find_target_basic_blocks(proj, targets)
    if not target_addrs:
        print("No targets in the binary found! (Exiting...)")
        exit()

    # Prepare the CFG with the target nodes and entry node
    #cfg = proj.analyses.CFGEmulated(
    #    keep_state=True,
    #    # Should be incrased if targets not found!
    #    max_iterations=50
    #)
    cfg = proj.analyses.CFGFast()

    target_nodes = []
    for target_addr in target_addrs: 
        target_node = cfg.get_any_node(target_addr, anyaddr=True)
        if not target_node:
            print("Warning: Could not found basic block for address: 0x{:x} ({}).".format(target_addr, target_addr))
            continue
        target_nodes.append(target_node)

    results = calculate_distance(cfg, target_nodes)
    results = sorted(
        results,
        key=lambda x: x[0].addr
    )

    # Store the results
    destination_path = sys.argv[3]
    with open(destination_path, "w") as file_obj:
        content = "\n".join(
            f"{hex(bb_node.addr)},{bb_distance}"
            for bb_node, bb_distance in results
        )
        file_obj.write(content)


if __name__ == "__main__":
    main()
