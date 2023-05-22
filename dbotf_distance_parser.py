#!/usr/bin/env python3
import angr
import networkx
import os
import sys
import itertools
import math


def find_files_from_distances(proj, distances):
    """Find the binary address of the targets and return it as list."""
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
    for addr, distance_value in distances:
        target_distances[addr] = distance_value

    results = {}
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

        value = target_distances.pop(addr, None)
        if value:
            source_tuple = (source_file_mapping, line)
            previous_distance = results.get(source_tuple, 0)
            if previous_distance < value:
                results[source_tuple] = value

    target_distances_len = len(target_distances)
    if target_distances_len > 0:
        print(
            f"Warning, not all distances was found in the binary! (Amount: {target_distances_len} from {len(distances)})"
        )
    return [(source_mapping[0], source_mapping[1], distance) for source_mapping, distance in results.items()]


def main():
    if len(sys.argv) != 4:
        print("Not enough arguments!")
        usage_str = f"{sys.argv[0]} [Binary] [dbotf_distance.cfg.txt] [Output]"
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
            
            addr, distance = distance_split
            addr = int(addr, base=0)
            distance = float(distance)
            targets.append(
                (addr, distance)
            )

    if not targets:
        print("The distance file has no targets!")
        exit(1)

    binary_path = sys.argv[1]

    # "Entry Point" - Depending on the binary :-/
    #proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': 0, "force_rebase": True})
    proj = angr.Project(binary_path, load_debug_info=True, auto_load_libs=False)

    cfg_distances = find_files_from_distances(proj, targets)
    cfg_distances = sorted(
        cfg_distances,
        key=lambda x: x[0]
    )

    # Store the results
    destination_path = sys.argv[3]
    with open(destination_path, "w") as file_obj:
        content = "\n".join(
            f"{file_node}:{souce_line},{bb_distance}"
            for file_node, souce_line, bb_distance in cfg_distances
        )
        file_obj.write(content)


if __name__ == "__main__":
    main()
