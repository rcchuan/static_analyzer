"""
Control Flow Graph Builder
Constructs CFG from IR nodes with basic block partitioning
"""
from typing import List, Optional
from core.ir import IRNode, NodeType, BasicBlock, CFGEdge, AnalysisResult


class CFGBuilder:
    def __init__(self):
        self._block_counter = 0

    def _new_block(self, label: str = "") -> BasicBlock:
        bb = BasicBlock(id=self._block_counter, label=label)
        self._block_counter += 1
        return bb

    def build(self, result: AnalysisResult) -> AnalysisResult:
        if result.ir_root is None:
            return result
        self._block_counter = 0
        blocks, edges = [], []
        entry     = self._new_block("ENTRY")
        exit_block = self._new_block("EXIT")
        blocks.append(entry)

        if result.ir_root.children:
            self._process_nodes(
                result.ir_root.children, entry, exit_block, blocks, edges,
                top_level=True)

        # Make sure EXIT is always in the list
        if exit_block not in blocks:
            blocks.append(exit_block)
        else:
            # Move EXIT to the end for readability
            blocks.remove(exit_block)
            blocks.append(exit_block)

        result.cfg_blocks = blocks
        result.cfg_edges  = edges
        return result

    # ──────────────────────────────────────────────────────────────────
    def _process_nodes(self, nodes: List[IRNode], current: BasicBlock,
                       exit_block: BasicBlock, blocks: List, edges: List,
                       top_level: bool = False) -> BasicBlock:
        for node in nodes:
            current = self._process_node(
                node, current, exit_block, blocks, edges, top_level=top_level)
        return current

    def _process_node(self, node: IRNode, current: BasicBlock,
                      exit_block: BasicBlock, blocks: List, edges: List,
                      top_level: bool = False) -> BasicBlock:

        # ── Top-level FUNCTION declaration ────────────────────────────
        # Each function gets its own sub-graph rooted at a fresh func_block
        # connected FROM ENTRY (not from whatever block the previous function
        # left behind).  This prevents dead_code artefacts from one function
        # becoming predecessors of the next function.
        if node.node_type == NodeType.FUNCTION:
            func_block = self._new_block(f"func_{node.value}")
            blocks.append(func_block)

            if top_level:
                # Always connect top-level functions directly from ENTRY
                # so they are reachable from the graph root.
                entry_block = blocks[0]   # ENTRY is always blocks[0]
                self._add_edge(entry_block, func_block, "", edges)
            else:
                # Nested / inner function: connect from current position
                self._add_edge(current, func_block, "", edges)

            func_exit = self._process_nodes(
                node.children, func_block, exit_block, blocks, edges,
                top_level=False)

            # Connect the function's last block to EXIT if it didn't
            # already terminate with an explicit RETURN
            if func_exit is not exit_block and "dead_code" not in func_exit.label:
                self._add_edge(func_exit, exit_block, "", edges)

            # Return CURRENT (unchanged) so the next top-level node
            # continues from the right place, not from inside this function
            return current if top_level else func_exit

        # ── IF / else-if ─────────────────────────────────────────────
        elif node.node_type == NodeType.IF:
            current.instructions.append(node)
            true_block  = self._new_block("if_true")
            false_block = self._new_block("if_false")
            merge_block = self._new_block("if_merge")
            blocks.extend([true_block, false_block, merge_block])

            self._add_edge(current, true_block,  "true",  edges)
            self._add_edge(current, false_block, "false", edges)

            if_children = node.children
            true_end = self._process_nodes(
                if_children[:len(if_children)//2 + 1] if if_children else [],
                true_block, exit_block, blocks, edges)
            false_end = false_block

            self._add_edge(true_end,  merge_block, "", edges)
            self._add_edge(false_end, merge_block, "", edges)
            return merge_block

        # ── Loops ─────────────────────────────────────────────────────
        elif node.node_type in (NodeType.WHILE, NodeType.FOR, NodeType.FOREACH):
            loop_header = self._new_block("loop_header")
            loop_body   = self._new_block("loop_body")
            loop_exit   = self._new_block("loop_exit")
            blocks.extend([loop_header, loop_body, loop_exit])

            self._add_edge(current,     loop_header, "",      edges)
            self._add_edge(loop_header, loop_body,   "true",  edges)
            self._add_edge(loop_header, loop_exit,   "false", edges)

            body_end = self._process_nodes(
                node.children, loop_body, loop_exit, blocks, edges)
            self._add_edge(body_end, loop_header, "back", edges)
            return loop_exit

        # ── Exception handling ────────────────────────────────────────
        elif node.node_type == NodeType.TRY:
            try_block     = self._new_block("try")
            catch_block   = self._new_block("catch")
            finally_block = self._new_block("finally")
            blocks.extend([try_block, catch_block, finally_block])

            self._add_edge(current,    try_block,     "",          edges)
            self._add_edge(try_block,  catch_block,   "exception", edges)
            self._add_edge(try_block,  finally_block, "",          edges)
            self._add_edge(catch_block, finally_block, "",         edges)
            return finally_block

        # ── RETURN / BREAK / CONTINUE ────────────────────────────────
        elif node.node_type == NodeType.RETURN:
            current.instructions.append(node)
            self._add_edge(current, exit_block, "", edges)
            # Create a synthetic dead_code block to absorb any IR nodes that
            # the parser emits after the return (closing braces, etc.).
            # This block is intentionally NOT reported as dead code — it is a
            # CFG artefact, not real user code.  The dataflow analyser skips
            # blocks whose label contains "dead_code".
            dead = self._new_block("dead_code")
            blocks.append(dead)
            self._add_edge(dead, exit_block, "", edges)  # keep graph connected
            return dead

        elif node.node_type == NodeType.BREAK:
            current.instructions.append(node)
            self._add_edge(current, exit_block, "", edges)
            dead = self._new_block("dead_code")
            blocks.append(dead)
            self._add_edge(dead, exit_block, "", edges)
            return dead

        # ── Default: plain statement ─────────────────────────────────
        else:
            current.instructions.append(node)
            return current

    # ──────────────────────────────────────────────────────────────────
    def _add_edge(self, src: BasicBlock, dst: BasicBlock, label: str,
                  edges: List[CFGEdge]):
        edge = CFGEdge(src=src, dst=dst, label=label)
        edges.append(edge)
        if dst not in src.successors:
            src.successors.append(dst)
        if src not in dst.predecessors:
            dst.predecessors.append(src)