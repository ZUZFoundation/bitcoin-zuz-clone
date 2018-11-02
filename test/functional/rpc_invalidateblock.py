#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the invalidateblock RPC."""

from test_framework.test_framework import ZuzcoinTestFramework
from test_framework.util import *

class InvalidateTest(ZuzcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.log.info("Make sure we repopulate setBlockIndexCandidates after InvalidateBlock:")
        self.log.info("Mine 104 blocks on Node 0")
        self.nodes[0].generate(104)
        assert(self.nodes[0].getblockcount() == 104)
        besthash = self.nodes[0].getbestblockhash()

        self.log.info("Mine competing 6 blocks on Node 1")

        #Mining extra blocks to properly fork elements chain
        print("Mine competing 106 blocks on Node 1")
        self.nodes[1].generate(100)
        self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(), 1)
>>>>>>> elements/elements-0.14.1:qa/rpc-tests/invalidateblock.py
        self.nodes[1].generate(6)
        assert(self.nodes[1].getblockcount() == 106)

        self.log.info("Connect nodes to force a reorg")
        connect_nodes_bi(self.nodes,0,1)
        sync_blocks(self.nodes[0:2])
        assert(self.nodes[0].getblockcount() == 106)
        badhash = self.nodes[1].getblockhash(102)

        self.log.info("Invalidate block 2 on node 0 and verify we reorg to node 0's original chain")
        self.nodes[0].invalidateblock(badhash)
        newheight = self.nodes[0].getblockcount()
        newhash = self.nodes[0].getbestblockhash()
        if (newheight != 104 or newhash != besthash):
            raise AssertionError("Wrong tip for node0, hash %s, height %d"%(newhash,newheight))

        self.log.info("Make sure we won't reorg to a lower work chain:")
        connect_nodes_bi(self.nodes,1,2)
        self.log.info("Sync node 2 to node 1 so both have 106 blocks")
        sync_blocks(self.nodes[1:3])
        assert(self.nodes[2].getblockcount() == 106)
        self.log.info("Invalidate block 105 on node 1 so its tip is now at 104")
        self.nodes[1].invalidateblock(self.nodes[1].getblockhash(105))
        assert(self.nodes[1].getblockcount() == 104)
        self.log.info("Invalidate block 103 on node 102, so its tip is now 102")
        self.nodes[2].invalidateblock(self.nodes[2].getblockhash(103))
        assert(self.nodes[2].getblockcount() == 102)
        self.log.info("..and then mine a block")
        #self.nodes[2].generate(1)
        self.log.info("Verify all nodes are at the right height")
        time.sleep(5)
        for i in range(3):
            print(i,self.nodes[i].getblockcount())
        assert(self.nodes[2].getblockcount() == 102)
        assert(self.nodes[0].getblockcount() == 104)
        node1height = self.nodes[1].getblockcount()
        if node1height < 104:
            raise AssertionError("Node 1 reorged to a lower height: %d"%node1height)

if __name__ == '__main__':
    InvalidateTest().main()
