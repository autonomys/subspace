# Feed Processor
Feed Processor defines some useful abstractions that are used during the life cycle of the Feed and its objects.
We can provide some custom logic specific to the Feed by implementing a Custom Feed Processor.

## Feed Metadata
Before an object is added to Subspace storage, `put` on Feed processor to give the impl an opportunity to run the object
through their custom logic and returns some metadata about the object. Metadata is then stored in the runtime overwriting
any metadata of the previous object. The default implementation of Feed processor gives empty metadata about the object.

## Feed object mapping
Feed indexes the objects in the DSN using offsets within the Block the object is present in. `object_mappings` is the 
only that must be implemented by the Feed processor. Since DSN is a key value store, there are two different ways keys
are derived for given data at the offset within the block
- Key derived from content. Feeds use Sha256 to derive the key for the data at the offset.
- Key provided by the feed processor. Feed processor implementations can instead provide a key for object at the offset.

## Examples
### Content based addressing with default hasher
```rust
use pallet_feeds::feed_processor::{FeedProcessor, FeedObjectMapping};
struct IPFSLike;
impl<FeedId> FeedProcessor<FeedId> for IPFSLike {
    /// Maps the entire object as content.
    fn object_mappings(&self, _feed_id: FeedId, _object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping::Content { offset: 0 }]
    }
}
```
This implements a Content addressable Feed using default Hasher. The entire object is treated as data and hence the offset is zero.

### Content based addressing using custom Hasher
```rust
use sp_runtime::traits::{BlakeTwo256, Hash};
use pallet_feeds::feed_processor::{FeedProcessor, FeedObjectMapping};
struct IPFSLike;
impl<FeedId> FeedProcessor<FeedId> for IPFSLike {
    /// Maps the entire object as content.
    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        vec![FeedObjectMapping::Custom { key: BlakeTwo256::hash(object).as_bytes().to_vec(), offset: 0 }]
    }
}
```
This implements a Content addressable Feed using BlakeTwo256 hasher. The entire object is treated as data and hence the offset is zero.
