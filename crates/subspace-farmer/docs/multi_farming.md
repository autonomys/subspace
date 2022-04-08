Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.

Each plot is limited by `max_plot_size` constant (which says how many pieces can
be stored inside individual plot) from the consensus, so if there will be some
piece out of this max plot size solution with it will be rejected by the
consensus.

So in order to utilize any amount of disk space we want to create multiple plots.
