`Plot` struct is an abstraction on top of both plot and tags database.

It converts requests to internal reads/writes to the plot and tags database. It
prioritizes reads over writes by having separate queues for reads and writes requests, read
requests are executed until exhausted after which at most 1 write request is handled and the
cycle repeats. This allows finding solution with as little delay as possible while introducing
changes to the plot at the same time (re-plotting on salt changes or extending plot size).
