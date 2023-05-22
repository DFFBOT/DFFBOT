import os
import click


"""
From the click documentation to allow hex ints as input.
"""
class BasedIntParamType(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        try:
            if value[:2].lower() == "0x":
                return int(value[2:], 16)
            elif value[:1] == "0":
                return int(value, 8)
            return int(value, 10)
        except TypeError:
            self.fail(
                "expected string for int() conversion, got "
                f"{value!r} of type {type(value).__name__}",
                param,
                ctx,
            )
        except ValueError:
            self.fail(f"{value!r} is not a valid integer", param, ctx)

BASED_INT = BasedIntParamType()


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


def find_target_basic_blocks_with_distance(proj, targets):
    """Find the binary address of the targets and return it as list with distances.

    targets: List of ('source_file', line, distance) tuples. E.g. [('main.c', 9, 0.5)]
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


def find_files_from_dffbot_distances(proj, distances):
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

    return [
        (source_mapping[0], source_mapping[1], distance)
        for source_mapping, distance in results.items()
    ]
