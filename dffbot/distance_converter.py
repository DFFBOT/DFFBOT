import click

from dffbot.utils import BASED_INT, find_target_basic_blocks_with_distance, find_files_from_dffbot_distances


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


@click.command(
    name="convert-aflgo-to-dffbot",
    short_help="Convert the AFLGO distances to DFFBOT distances",
)
@click.argument('binary_file', type=click.Path(exists=True))
@click.argument('targets', type=click.File('r'))
@click.argument('output', type=click.File('w'))
@click.option('-b', '--base-addr', 'custom_base_addr', type=BASED_INT, required=False, help="Set a custom base_addr for the binary")
def convert_aflgo_to_dffbot(binary_file, targets, output, custom_base_addr):
    # Parse the targets
    aflgo_targets = []
    bbtargets_reader = targets.readlines()
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
        aflgo_targets.append(
            (source_target, line, distance)
        )

    if not targets:
        click.echo("The distance file has no targets!")
        exit(1)
    
    # Import the binary
    # "Base address" - Depending on the binary
    # angr struggles sometimes to map it correctly, use objdump, elftools, Ghidra
    # or BinaryNinja to verify it!
    import angr
    if custom_base_addr is None:       
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': custom_base_addr, "force_rebase": True})
    else:
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False)
    
    target_addrs = find_target_basic_blocks_with_distance(proj, aflgo_targets)
    cfg = proj.analyses.CFGFast()
    target_bb_blocks = find_bb_targets_from_addrs(proj, cfg, target_addrs)

    # Store the results
    content = "\n".join(
        f"{hex(node_addr)},{bb_distance}"
        for node_addr, bb_distance in target_bb_blocks
    )
    output.write(content)


@click.command(
    name="convert-dffbot-to-aflgo",
    short_help="Convert the DFFBOT distances to AFLGo distances",
)
@click.argument('binary_file', type=click.Path(exists=True))
@click.argument('targets', type=click.File('r'))
@click.argument('output', type=click.File('w'))
@click.option('-b', '--base-addr', 'custom_base_addr', type=BASED_INT, required=False, help="Set a custom base_addr for the binary")
def convert_dffbot_to_aflgo(binary_file, targets, output, custom_base_addr):
    # Parse the targets
    aflgo_targets = []
    bbtargets_reader = targets.readlines()
    for bbtarget_line in bbtargets_reader:
        distance_split = bbtarget_line.split(",")
        if len(distance_split) != 2:
            error_str = f"Wrong format of line: {bbtarget_line}"
            raise ValueError(error_str)
        
        addr, distance = distance_split
        addr = int(addr, base=0)
        distance = float(distance)
        aflgo_targets.append(
            (addr, distance)
        )

    if not aflgo_targets:
        click.echo("The distance file has no targets!")
        exit(1)
    
    # Import the binary
    # "Base address" - Depending on the binary
    # angr struggles sometimes to map it correctly, use objdump, elftools, Ghidra
    # or BinaryNinja to verify it!
    import angr
    if custom_base_addr is None:       
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False, main_opts={'base_addr': custom_base_addr, "force_rebase": True})
    else:
        proj = angr.Project(binary_file, load_debug_info=True, auto_load_libs=False)
    
    cfg_distances = find_files_from_dffbot_distances(proj, aflgo_targets)
    cfg_distances = sorted(
        cfg_distances,
        key=lambda x: x[0]
    )

    # Store the results
    content = "\n".join(
        f"{file_node}:{souce_line},{bb_distance}"
        for file_node, souce_line, bb_distance in cfg_distances
    )
    output.write(content)