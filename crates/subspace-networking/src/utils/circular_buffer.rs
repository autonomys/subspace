//! It's a copy of the `CircularBuffer` from `queues = "1.1.0"`
//! We need a custom `remove_value` method for our use case.

#![allow(dead_code)]

/// Defines methods that would be expected on a queue data structure
pub trait IsQueue<T: Clone> {
    /// Adds a new value to a queue
    ///
    /// # Parameters
    /// - `val`: Value to add to the queue
    ///
    /// # Returns
    /// - `Ok(_)`: If the element add was successful.
    ///     - `Some(T)`: If adding an element resulted in the removal of an
    ///         existing one (in the case of a circular buffer, for instance)
    ///     - `None`: Adding an element did not return any value
    /// - `Error`: If the element add was unsuccessful
    ///
    /// # Errors
    /// Attempting to add an element to a full queue that does not allow for
    /// overflow will return an error.
    fn add(&mut self, val: T) -> Result<Option<T>, &str>;

    /// Removes an element from the queue and returns it
    ///
    /// For queues with default values, removing an element will add a new
    /// default value into the queue.
    ///
    /// # Returns
    /// - `Ok(T)`: The oldest element in the queue
    /// - `Error`
    ///
    /// # Errors
    /// Returns an error if an attempt is made to remove an element from
    /// an empty queue
    fn remove(&mut self) -> Result<T, &str>;

    /// Peek at the head of the queue
    ///
    /// # Returns
    /// - `Ok(T)`: The next element scheduled for removal from the queue
    /// - `Error`
    ///
    /// # Errors
    /// Returns an error if an attempt is made to peek into an empty queue
    fn peek(&self) -> Result<T, &str>;

    /// Gets the size of the queue
    ///
    /// # Returns
    /// The number of elements in the queue. Note, this _includes_ default
    /// values when specified, which means that the `size` of a queue with
    /// default values should always be equal to its `capacity`
    fn size(&self) -> usize;

    /// Remove all entries of a given value.
    fn remove_value(&mut self, val: &T);
}

/// Represents a FIFO `CircularBuffer<T>` data structure.
///
/// This structure is a limited capacity queue, with optional provisions
/// for default values. Under normal circumstances, the `size` of the
/// queue grows until it reaches its `capacity`, at which point any
/// further additions push out its oldest member.
///
/// If default values are specified, then the `size` of the queue
/// is always equal to its `capacity`, with empty slots occupied by the
/// specified default value.
///
/// # Type parameters
/// - `T`: Any type that implements the `Clone` trait.
///
/// # Examples
///
/// ```
/// # use subspace_networking::utils::circular_buffer::*;
/// # fn main() {
/// let mut cbuf = CircularBuffer::<isize>::new(3);
/// let mut cbuf_def = CircularBuffer::with_default(3, 0isize);
///
/// // Check sizes
/// assert_eq!(cbuf.size(), 0);
/// assert_eq!(cbuf_def.size(), 3);
///
/// // Add elements
/// cbuf.add(6);
/// cbuf_def.add(7);
///
/// // Peek at the next element scheduled for removal
/// assert_eq!(cbuf.peek().unwrap(), 6);
/// assert_eq!(cbuf_def.peek().unwrap(), 0);
/// # }
/// ```
#[derive(Debug)]
pub struct CircularBuffer<T: Clone> {
    queue: Vec<T>,
    capacity: usize,
    default_value: Option<T>,
}

impl<T: Clone> CircularBuffer<T> {
    /// Default `CircularBuffer<T>` initializer
    ///
    /// # Returns
    /// A new, empty `CircularBuffer<T>`
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::*;
    /// let cbuf: CircularBuffer<isize> = CircularBuffer::new(3);
    /// assert_eq!(cbuf.size(), 0);
    /// assert_eq!(cbuf.capacity(), 3);
    /// ```
    pub fn new(capacity: usize) -> CircularBuffer<T> {
        CircularBuffer {
            queue: vec![],
            capacity,
            default_value: None,
        }
    }

    /// Create a `CircularBuffer<T>` with default values
    ///
    /// # Returns
    /// A new `CircularBuffer<T>` filled with default values
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::*;
    /// let cbuf_def = CircularBuffer::with_default(3, -1isize);
    /// assert_eq!(cbuf_def.size(), 3);
    /// assert_eq!(cbuf_def.capacity(), 3);
    /// assert_eq!(cbuf_def.peek(), Ok(-1));
    /// ```
    pub fn with_default(capacity: usize, default_value: T) -> CircularBuffer<T> {
        let queue = vec![default_value.clone(); capacity];

        CircularBuffer {
            queue,
            capacity,
            default_value: Some(default_value),
        }
    }

    /// Gets the capacity of the `CircularBuffer<T>`
    ///
    /// # Returns
    /// The number of allowed elements in the buffer
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::CircularBuffer;
    /// let mut cbuf: CircularBuffer<isize> = CircularBuffer::new(3);
    /// assert_eq!(cbuf.capacity(), 3);
    /// ```
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl<T: Clone + PartialEq> IsQueue<T> for CircularBuffer<T> {
    /// Adds an element to a circular buffer
    ///
    /// # Parameters
    /// - `val`: Value to add to the buffer
    ///
    /// # Returns
    /// - `Ok(Some(T))`: The oldest value in the buffer, in case the addition
    ///     causes an overflow.
    /// - `Ok(None)`: Nothing, if the buffer has room for the added element
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::*;
    /// let mut cbuf: CircularBuffer<isize> = CircularBuffer::new(3);
    /// let mut cbuf_def = CircularBuffer::with_default(3, 5isize);
    /// assert_eq!(cbuf.add(42), Ok(None));
    /// assert_eq!(cbuf_def.add(42), Ok(Some(5)));
    /// ```
    fn add(&mut self, val: T) -> Result<Option<T>, &str> {
        if self.queue.len() < self.capacity {
            self.queue.push(val);
            Ok(None)
        } else {
            self.queue.push(val);
            Ok(Some(self.queue.remove(0usize)))
        }
    }

    /// Removes an element from the circular buffer and returns it.
    ///
    /// For circular buffers with default values, removing an element will add
    /// a new default value into the buffer.
    ///
    /// # Returns
    /// - `Ok(T)`: The oldest element in the buffer
    /// - `Error`
    ///
    /// # Errors
    /// Returns an error if an attempt is made to remove an element from
    /// an empty buffer
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::*;
    /// let mut cbuf: CircularBuffer<isize> = CircularBuffer::new(3);
    /// cbuf.add(42);
    /// assert_eq!(cbuf.remove(), Ok(42));
    /// assert_eq!(cbuf.size(), 0);
    ///
    /// let mut cbuf_def = CircularBuffer::with_default(3, 4isize);
    /// cbuf_def.add(42);
    /// assert_eq!(cbuf_def.remove(), Ok(4));
    /// ```
    fn remove(&mut self) -> Result<T, &str> {
        if !self.queue.is_empty() {
            if let Some(val) = self.default_value.clone() {
                self.queue.push(val);
            };
            Ok(self.queue.remove(0usize))
        } else {
            Err("The Buffer is empty")
        }
    }

    /// Peek at the head of the circular buffer
    ///
    /// # Returns
    /// - `Ok(T)`: The next element scheduled for removal from the buffer
    /// - `Error`
    ///
    /// # Errors
    /// Returns an error if an attempt is made to peek into an empty buffer
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::*;
    /// let mut cbuf: CircularBuffer<isize> = CircularBuffer::new(3);
    /// cbuf.add(42);
    /// assert_eq!(cbuf.peek(), Ok(42));
    /// ```
    fn peek(&self) -> Result<T, &str> {
        match self.queue.first() {
            Some(val) => Ok(val.clone()),
            None => Err("The Queue is empty"),
        }
    }

    /// Gets the size of the circular buffer
    ///
    /// # Returns
    /// The number of elements in the buffer. Note, this _includes_ default
    /// values, which means that the `size` of a buffer with default values
    /// should always be equal to its `capacity`
    ///
    /// # Examples
    ///
    /// ```
    /// # use subspace_networking::utils::circular_buffer::*;
    /// let mut cbuf: CircularBuffer<isize> = CircularBuffer::new(3);
    /// assert_eq!(cbuf.size(), 0);
    /// cbuf.add(42);
    /// assert_eq!(cbuf.size(), 1);
    /// ```
    fn size(&self) -> usize {
        self.queue.len()
    }

    /// Remove all entries of a given value.
    fn remove_value(&mut self, val: &T) {
        self.queue.retain(|item| item != val);
    }
}
