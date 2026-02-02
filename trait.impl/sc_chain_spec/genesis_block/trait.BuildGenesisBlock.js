(function() {
    var implementors = Object.fromEntries([["domain_block_builder",[["impl&lt;CClient, CBlock, Block, B, E&gt; BuildGenesisBlock&lt;Block&gt; for <a class=\"struct\" href=\"domain_block_builder/struct.CustomGenesisBlockBuilder.html\" title=\"struct domain_block_builder::CustomGenesisBlockBuilder\">CustomGenesisBlockBuilder</a>&lt;CClient, CBlock, Block, B, E&gt;<div class=\"where\">where\n    Block: BlockT,\n    Block::Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;H256&gt;,\n    B: Backend&lt;Block&gt;,\n    E: RuntimeVersionOf,\n    CBlock: BlockT,\n    CBlock::Hash: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;H256&gt;,\n    CClient: ProvideRuntimeApi&lt;CBlock&gt; + HeaderBackend&lt;CBlock&gt;,\n    CClient::Api: DomainsApi&lt;CBlock, Block::Header&gt;,</div>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[926]}