import click

from dffbot.utils import BASED_INT


@click.command(
    name="generate-distances",
    short_help="Calculate the distances from the given binary and memory locations",
)
@click.argument('binary_file', type=click.Path(exists=True))
@click.argument('output', type=click.File('w'))
@click.argument('targets', type=BASED_INT, nargs=-1)
@click.option('-b', '--base-addr', 'custom_base_addr', type=BASED_INT, required=False, help="Set a custom base_addr for the binary")
@click.option('--aflgo-distances/--no-aflgo-distances', 'use_aflgo_distances', default=False)
def generate_distances(binary_file, output, targets, custom_base_addr, use_aflgo_distances):
    import angr
    
    if use_aflgo_distances:
        from dffbot.distance_utils import AFLGoDistanceGenerator
        distance_generator_cls = AFLGoDistanceGenerator
    else:
        from dffbot.distance_utils import DFFBOTDistanceGenerator
        distance_generator_cls = DFFBOTDistanceGenerator

    # Import the binary
    # "Base address" - Depending on the binary
    # angr struggles sometimes to map it correctly, use objdump, elftools, Ghidra
    # or BinaryNinja to verify it!
    if custom_base_addr is None:       
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': custom_base_addr, "force_rebase": True})
    else:
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False)
 
    # Calculate the distances
    cfg = proj.analyses.CFGFast()
    distance_calculator = distance_generator_cls()
    distances = distance_calculator(cfg, targets)

    # Store it on the given file path
    distances_result = distance_calculator.format_result(distances)
    content = "\n".join(
        line_i
        for line_i in distances_result
    )
    output.write(content)


@click.command(
    name="generate-distances-from-debug",
    short_help="Calculate the distances from the given binary with debug informations and a BBTargets file",
)
@click.argument('binary_file', type=click.Path(exists=True))
@click.argument('targets', type=click.Path(exists=True))
@click.argument('output', type=click.File('w'))
@click.option('-b', '--base-addr', 'custom_base_addr', type=BASED_INT, required=False, help="Set a custom base_addr for the binary")
@click.option('--aflgo-distances/--no-aflgo-distances', 'use_aflgo_distances', default=False)
def generate_distances_from_debug(binary_file, targets, output, custom_base_addr, use_aflgo_distances):
    # Parse the BBTargets.txt file
    parsed_targets = []
    with open(targets, "r") as file_obj:
        bbtargets_reader = file_obj.readlines()
        for bbtarget_line in bbtargets_reader:
            splitted_bbtarget = bbtarget_line.split(":")
            if len(splitted_bbtarget) != 2:
                error_str = f"Wrong format of BBtarget: {bbtarget_line}"
                raise ValueError(error_str)
            
            bbtarget, line = splitted_bbtarget
            line = int(line)
            parsed_targets.append(
                (bbtarget, line)
            )
    
    import angr
    from dffbot.distance_utils import find_target_basic_blocks
    
    if use_aflgo_distances:
        from dffbot.distance_utils import AFLGoDistanceGenerator
        distance_generator_cls = AFLGoDistanceGenerator
    else:
        from dffbot.distance_utils import DFFBOTDistanceGenerator
        distance_generator_cls = DFFBOTDistanceGenerator

    # Import the binary
    # "Base address" - Depending on the binary
    # angr struggles sometimes to map it correctly, use objdump, elftools, Ghidra
    # or BinaryNinja to verify it!
    if custom_base_addr is None:       
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': custom_base_addr, "force_rebase": True})
    else:
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False)

    # Parse the targets
    target_addrs = find_target_basic_blocks(proj, parsed_targets)
    
    # Calculate the distances
    cfg = proj.analyses.CFGFast()
    distance_calculator = distance_generator_cls()
    distances = distance_calculator(cfg, target_addrs)

    # Store it on the given file path
    distances_result = distance_calculator.format_result(distances)
    content = "\n".join(
        line_i
        for line_i in distances_result
    )
    output.write(content)