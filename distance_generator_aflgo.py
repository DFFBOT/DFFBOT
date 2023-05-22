#!/usr/bin/env python3
import angr
import networkx
import os
import sys
import itertools
import math

FUNCTION_PATH_CONSTANT = 10


def find_target_basic_blocks(proj, targets):
    """Find the binary address of the targets and return it as list.

    targets: List of ('source_file', line) tuples. E.g. [('main.c', 9)]
    """
    compilation_dir = proj.loader.all_elf_objects[0].compilation_units[0].comp_dir
    if compilation_dir.endswith("build"):
        compilation_dir = os.path.join(compilation_dir, "..")
    addr_mapping = proj.loader.main_object.addr_to_line
    results = []
    for target in targets:
        result = None
        for addr, mapping in addr_mapping.items():
            source_file_mapping, line = mapping
            source_file_mapping = os.path.relpath(source_file_mapping, compilation_dir)

            if source_file_mapping != target[0]:
                continue

            if target[1] != line:
                continue

            result = addr
            break
        
        if result is None:
            raise ValueError("Could not find mapping!")
        results.append(result)
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


"""
Formel Recap:
- m ist ein Target-Knoten => Distance = 0
- m besitzt eine Menge von erreichbaren Knoten im Callgraph: Distanzen im Callgraph
- Sonst: Über den CFG gehen...

# Alt
def calculate_distance_from_bb_node(cfg, bb_node, targets):
    shortest_distance = math.inf
    for target_node in targets:
        # Distance = 0 if the nodes are the same
        if bb_node == target_node:
            return 0.0

        # Current distance value
        current_distance = math.inf

        # function level distance
        function_distance_not_found = False
        try:
            # (|Path|^-1)^-1 = |Path|
            target_fb_path_length = networkx.shortest_path_length(
                cfg.functions.callgraph,
                bb_node.addr,
                target_node.function_address
            )
            current_distance = target_fb_path_length * FUNCTION_PATH_CONSTANT
        except (networkx.NetworkXNoPath, networkx.exception.NodeNotFound) as _:
            function_distance_not_found = True
        
        if function_distance_not_found:
            try:
                # Basic Block level distance
                # Same as function level distance
                # The transitive relation is automaticly done by networkx
                current_distance = networkx.shortest_path_length(
                    cfg.graph, bb_node, target_node
                )
            except (networkx.NetworkXNoPath, networkx.exception.NodeNotFound) as _:
                pass

        if current_distance < shortest_distance:
            shortest_distance = current_distance
    return shortest_distance
"""

def calculate_cg_distance(cfg, bb_node, targets):
    callgraph_subnodes = cfg.functions.callgraph.successors(bb_node.function_address)
    peek_node = next(callgraph_subnodes, None)
    if peek_node:
        callgraph_subnodes_gen = itertools.chain((peek_node,), callgraph_subnodes)
    else:
        callgraph_subnodes_gen = (bb_node.function_address,)

    function_distance = math.inf
    for cg_node in callgraph_subnodes:
        local_distance = 0.0
        found_node = False
        for target_node in targets:
        # Calculate function level distance of target_i
            target_fb_path_length = 0.0
            try:
                target_fb_path_length = networkx.shortest_path_length(
                    cfg.functions.callgraph,
                    cg_node,
                    target_node.function_address
                )
                target_fb_path_length += 1.0
                local_distance += 1.0 / target_fb_path_length
                found_node = True
            except ZeroDivisionError:
                # We do not increase local_distance because
                # of the definition, we are basicly adding
                # a "0" to the distance
                found_node = True
                continue
            except (networkx.NetworkXNoPath, networkx.exception.NodeNotFound) as _:
                continue
        
        if not found_node:
            continue
        
        if local_distance != 0.0:
            cg_node_distance = 1.0 / local_distance
        else:
            cg_node_distance = 0.0

        if cg_node_distance < function_distance:
            function_distance = cg_node_distance
    return function_distance


def calculate_distance_from_bb_node(cfg, bb_node, targets):
    """d_b(m, T_b) formula from the paper."""

    # Check if bb_node is in the targets (m in T_b)
    for target_node in targets:
        # Distance = 0 if the nodes are the same
        if bb_node == target_node:
            return 0.0
    
    # Check if we can use the function level distance
    function_distance = calculate_cg_distance(cfg, bb_node, targets)    
    if function_distance != math.inf:
        return function_distance * FUNCTION_PATH_CONSTANT
    
    # Use basic block distance
    distance = math.inf
    queue = []
    for bb_node_successor in bb_node.successors:
        queue.append([1, bb_node_successor])
    
    candidates = []
    while queue:
        bb_successor_struct = queue.pop(0)
        queue_node = bb_successor_struct[1]
        function_distance = calculate_cg_distance(cfg, queue_node, targets)
        
        if function_distance != math.inf:
            total_distance = bb_successor_struct[0] + function_distance
            total_distance = 1 / total_distance
            candidates.append(total_distance)
            continue
        
        for queue_node_successor in queue_node.successors:
            next_node_struct = [bb_successor_struct[0] + 1, queue_node_successor]
            queue.append(next_node_struct)

    if candidates:
        distance = 1 / sum(candidates)
    return distance


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
        if bb_distance != math.inf:
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
    proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': 0, "force_rebase": True})

    target_addrs = find_target_basic_blocks(proj, targets)
    if not target_addrs:
        print("No targets in the binary found! (Exiting...)")
        exit()

    # Prepare the CFG with the target nodes and entry node
    cfg = proj.analyses.CFGEmulated(
        keep_state=True,
        # Should be incrased if targets not found!
        max_iterations=50
    )
    #cfg = proj.analyses.CFGFast()

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


# TODO: What happens on the aflgo compiler, if custom -WL (_start) function?
# (The compiler does the counting based )
