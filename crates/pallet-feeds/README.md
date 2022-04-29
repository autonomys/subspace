# Pallet Feeds

License: Apache-2.0

Pallet feeds provides the interactions with Subspace storage. The main design goal for Feeds is not only to push objects
to the Storage but also to provide a way for the for feed owners to inject some verification logic through `FeedProcessor`
impls.

# Calls

The pallet provides following calls.
1. Create(permissionless): Creates a new Feed for the caller
2. Update: Updates the Feeds with some initial data. All the underlying FeedProcessors
will be reinitialized.
3. Transfer: Transfers a feed from one owner to another
4. Close: Closes the feed and doesn't accept any new objects
5. Put: Puts a new object in the Feed. The object is passed to FeedProcessor for verification if any.

