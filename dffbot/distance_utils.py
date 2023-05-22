import os
import math
import networkx
import itertools

from dffbot.utils import find_target_basic_blocks


class DistanceGeneratorBase:
    def __init__(self):
        pass
    
    def find_start_node(self, cfg):
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
    
    def get_nodes_from_targets(self, cfg, targets):
        target_nodes = []
        for target_addr in targets: 
            target_node = cfg.get_any_node(target_addr, anyaddr=True)
            if not target_node:
                print("Warning: Could not found basic block for address: 0x{:x} ({}).".format(target_addr, target_addr))
                continue
            target_nodes.append(target_node)
        return target_nodes
    
    def format_result(self, target_nodes):
        target_nodes = sorted(
            target_nodes,
            key=lambda x: x[0].addr
        )
        result = list(
            f"{hex(bb_node.addr)},{bb_distance}"
            for bb_node, bb_distance in target_nodes
        )
        return result



class DFFBOTDistanceGenerator(DistanceGeneratorBase):

    def __init__(self):
        pass

    def calculate_distance_from_bb_node(self, cfg, bb_node, targets):
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


    def __call__(self, cfg, targets_addresses):
        entry_node = self.find_start_node(cfg)
        targets = self.get_nodes_from_targets(cfg, targets_addresses)
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

            bb_distance = self.calculate_distance_from_bb_node(cfg, bb_node, targets)
            if bb_distance != math.inf and bb_distance > 0.0:
                results.append((bb_node, bb_distance))
        return results


# This class needs to be fixed, the calculation is not correct.
# It tries always to use the function distance but the formula
# states that only basic block, which calls function are allowed
# to use this.

class AFLGoDistanceGenerator(DistanceGeneratorBase):

    def __init__(self):
        self.FUNCTION_PATH_CONSTANT = 10

    def calculate_cg_distance(self, cfg, bb_node, targets):
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
                    local_distance += 1.0 / (target_fb_path_length)
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

    def calculate_distance_from_bb_node(self, cfg, bb_node, targets):
        """d_b(m, T_b) formula from the paper."""

        # Check if bb_node is in the targets (m in T_b)
        for target_node in targets:
            # Distance = 0 if the nodes are the same
            if bb_node == target_node:
                return 0.0
        
        # Check if we can use the function level distance
        function_distance = self.calculate_cg_distance(cfg, bb_node, targets)    
        if function_distance != math.inf:
            return function_distance * self.FUNCTION_PATH_CONSTANT
        
        # Use basic block distance
        distance = math.inf
        queue = []
        for bb_node_successor in bb_node.successors:
            queue.append([1, bb_node_successor])
        
        candidates = []
        while queue:
            bb_successor_struct = queue.pop(0)
            queue_node = bb_successor_struct[1]
            function_distance = self.calculate_cg_distance(cfg, queue_node, targets)
            
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


    def __call__(self, cfg, targets_addresses):
        entry_node = self.find_start_node(cfg)
        targets = self.get_nodes_from_targets(cfg, targets_addresses)
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

            bb_distance = self.calculate_distance_from_bb_node(cfg, bb_node, targets)
            if bb_distance != math.inf and bb_distance > 0.0:
                results.append((bb_node, bb_distance))
        return results