Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.

## Motivation of this abstraction

We need to support to any amount of disk space for plotting, but we also want
to preserve a property of having same replication factor for all pieces. So
that's why we have a consensus side limit for maximum amount of pieces for each
plot (`max_plot_size` consensus constant). That forces farmers to create new
random keys for each individual plot in order to utilize all the space.

This structure abstracts creation of multiple `Plot`s, `Farming`s and
`Plotting`s, while glueing them up together.
