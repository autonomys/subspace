# Contributing

Thanks for considering contributing to Autonomys Network!

The best way to start is to join our [Forum](https://forum.subspace.network/) or
[Discord](https://discord.gg/subspace-network), [official website](https://subspace.network/) has a bunch of learning
materials too.

GitHub is primarily used by developers to work on new features and improvements, and to fix bugs. If you're not sure whether
you have an actual bug that needs to be fixed or you just want to ask a question, the forum is the best place for that.

This document describes expectations and recommendations that should make contributions such as issues and pull requests
on GitHub productive for everyone involved.

## Process optimized for maintainers

Autonomys Network is maintained by a small group of passionate individuals with limited time. The number of potential outside
contributors is much larger than number of maintainers, and the wider community of users is even bigger than that.

As such, the process of contributing to Autonomys Network needs to be optimized in such a way that it doesn't overwhelm
maintainers with unnecessary notifications, or questions that can be answered by wider community. Following the practices
defined in this document below, such that contributions can be processed in the most productive way, saves time and
makes for a better experience overall.

## Bugs, improvements and feature requests

These should be submitted in such a way that they are actionable by developers. Again, if you're unsure or just have a
question - use the forum, a GitHub issue can be created later if it is necessary.

Always search for similar topics already created on the forum or here on GitHub, before creating a new one. But don't
hijack threads that look somewhat similar, they are not necessarily the same, and might not have the same root cause.

### Bugs

For bug report to be actionable it should ideally follow the following template:

<details>
<summary>Click to see the template</summary>

### Steps to reproduce

1. On Ubuntu 22.04
2. Run `subspace-farmer-ubuntu-x86_64-gemini-1b-2022-jun-18 farm` from official release
3. Observe an error

### Expected result

Farmer starts successfully

### What happens instead

This error
```
error: The following required arguments were not provided:
    --reward-address <REWARD_ADDRESS>
    --plot-size <PLOT_SIZE>

USAGE:
    subspace-farmer-ubuntu-x86_64-gemini-1b-2022-jun-18 [OPTIONS] --reward-address <REWARD_ADDRESS> --plot-size <PLOT_SIZE>

For more information try --help
```

</details>

That is an invalid bug report, of course, but you get the idea of what it should look like.

Try to provide as much useful information as possible, but not too much and without rambling, so that developers can
quickly diagnose and address it.

### Improvements and feature requests

When there is something that can be improved or a feature is lacking, it is probably a good idea to start with the forum
and search for similar ideas. If there isn't a topic already, create one to see if this would be a welcome change.

Again, try to discuss with wider audience whether it is a good idea before reaching out to maintainers directly.

When it is necessary to create an issue here, try to describe in a concise way what the improvement or new feature
would look like, potentially using a similar template to [reporting bugs](#bugs), describing the expected user flow.

## Code contributions

Code contributions are more involved, but the simplest rule here is to observe what maintainers do, how existing code
looks like and mimic that, but we provide more specific requirements below.

### Code style

We follow traditional Rust code style with some clarifications and set in `rustfmt.toml`. We also follow all Clippy
lints (with rare suppressions). As such every commit should successfully pass `cargo fmt --check` and produce zero
warnings when running `cargo clippy`. This rule includes not just library and application code, but also examples and
tests.

Every file should end with one and exactly one new line, configure your IDE to insert it automatically. Lines should
not end with whitespace, this includes code, comments, documentation (`*.md` files), configs and everything else.

Pay attention to existing code and mimic its structure, for instance we keep dependencies in sorted order in `Cargo.toml`
and if you submit changes where new dependency is added out-of-order you're introducing unnecessary entropy and irritating
maintainers.

If there is an option between being smart with a tricky piece of code, or obvious, prefer obvious. Write idiomatic Rust
as well as you can, this often avoids the need for `.unwrap()`.

Struct definition and its implementation should be in the same file, ideally with nothing else in between.

In blockchain code use of `.unwrap()` is strictly forbidden and must never be used (except test code), use `.expect()`
instead. The `.expect()` message must convince the reviewer that it will never panic, or why panicking might be the
preferred outcome (this is rare). `.expect()` correctness should be derivable from local context if it is a standalone
function, or invariants of a data structure for an internal method. If it can't be guaranteed then `Result<T, E>` must be
used instead. There are rare exceptions to this such as block numbers that never exceed `u32` in Subspace.

Indexing into slices and similar data structures with `[]` should be avoided and replaced with `.get()` or similar
methods with explicit handling of cases where element doesn't exist.

Same goes about mathematical operations, especially in runtime logic, in most cases use explicit checked, wrapping or
saturating math, but don't use saturating math just to make things compile if business logic doesn't expect overflow to
ever happen, use checked math with `.expect()` in such cases or return an error. Avoid using `as` to convert, it can
silently truncate numbers. Prefer `into`, or use `try_into` and return the error (or `expect` if the conversion never
fails).

Unsafe code is to be avoided except in special cases. If you can't make the code compile and decide to use `unsafe` to
bypass compiler checks, chances are you're doing it wrong and should ask for help to avoid `unsafe`. When you do use
`unsafe` for valid reasons, just like with `.expect()`, you need to provide a `// SAFETY:` comment proof convincing
the reviewer that the code is sound, and can't be exploited with the public API from safe Rust.

If code is incomplete or has known issues, make sure to leave a TODO explaining what needs to be done or what isn't
handled properly. For big things consider creating an issue.

Prefer longer names of variables, variables with 1-3 characters are typically a bad choice. There are notable exceptions
like using `id` in entity data structure or `i` for a simple iteration over things. (Sometimes iteration is better expressed
using Rust iterator chains, without any iteration variables at all.)

Otherwise, look at existing code and try to do your best.

### Commits

Commits should tell a logical step by step story of the changes and ideally be individually meaningful. Use squashing
and rebasing during development, reorder commits if it makes more sense that way, there is great tooling out there for
these kinds of modifications.

Reviewers should be able to go through the commits one by one and understand what is being changed, with non-trivial
changes it is often very hard to review the final diff, so going through commits helps a lot. Commits should be
well-structured and there should be a reasonable number of them. 70 commits for 100 lines or changes is most likely bad,
same with one commit that changes many thousands of lines of code in various places at once (lock files are a frequent
and notable exception). Another exception is automated changes. If you do a mass rename, format, or `cargo clippy --fix`,
put the command in the commit message, so the reviewer can run it and check it produces the same diff.

If you work on a branch, and after a few commits notice that API introduced earlier doesn't work well, or you need to revert
some changes, amend the original commits instead of creating a new one much later. A reviewer going through individual
commits will likely have a comment about something that was already fixed, and will simply have to spend more time
reviewing changes back and forth.

Different kinds of changes should ideally be in different commits, if not different pull requests entirely. For instance
if you want to move something and change it, move in one commit so reviewer can have a quick look without thinking about
it too much and apply actual changes in a separate commit. Same with file renaming, if you rename file and change it
significantly in the same commit it'll make review very difficult, and likely convince Git that one file was
deleted and another file added, which breaks tooling for tracking file changes across renames.

It is sometimes the case that refactoring needs to be done during feature development, try to extract those
refactoring commits you have just done into a separate branch, submit it for review and rebase your working branch on
the refactoring branch so that the changes are clearly separated and easier to review as an example.

Please push your commits regularly, but not necessarily every commit since it may occupy CI time unnecessarily.

And finally, write commit messages in present tense (as opposed to past) and explain changes that should be done, for
instance here is a good example:
> finalize header at archiving depth and prune any forks at that number

Avoid garbage commit names like "fix", "wip", "🤦 x 2", "......", "AHHHHHHHHH" (those are real examples). In most cases
those commits probably shouldn't exist separately and better squashed with some other commit.

Here is a good article from GitHub on this topic:
[Write Better Commits, Build Better Projects](https://github.blog/2022-06-30-write-better-commits-build-better-projects/).

### Pull requests

It is important to remember that there are many people subscribed to the repository and any changes to pull request
will trigger notifications to tens, hundreds, potentially thousands of people. As such try to minimize them or else
many people, including maintainers, will unsubscribe and response time for issues and pull request changes will increase
dramatically.

Before even submitting pull request make sure to do a full self-review. This will allow you to spot minor issues like
typos or code you didn't intend to commit in the first place. At this stage use force-pushes to edit the original commits
and make sure you like the changes yourself.

As explained in [commits](#commits) section above, history should be clean and readable, ready for a reviewer to go
through and make sense of the changes proposed.

Make sure to test your own code locally and/or in CI before submitting a pull request to avoid numerous updates
afterwards to fix CI (remember, those changes will trigger extra notifications that could be avoided by following this
simple rule). Make sure to add new test cases if applicable.

Pull requests should be accompanied by a reasonable description. If the change is a trivial typo, the description can be
empty, but if changes are non-trivial, make sure to explain what the changes do, why, what were the alternatives and so on,
giving the reviewer proper context into the proposed changes. If there is a relevant issue or another pull request then
link it, if there is an issue that is resolved by proposed changes or PR that becomes obsolete, use
[GitHub linking keywords](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue).

Pull requests should be ready for review, avoid opening drafts that are frequently updated, in most cases you can share WIP
changes with someone just by sharing a branch diff, or a PR in your own fork. Drafts have a narrow and rare use case, use
them as last resort, otherwise they become a huge source of distraction due to number of notifications they generate. In most
cases you either want changes to be reviewed and merged, in which case a regular pull request should be created, or you don't
want a pull request at all. If an open pull request stops being ready for review or merging, close the PR, and re-open it when
it is ready for review again.

Once a PR is created, a rule of thumb is to avoid force pushes since it is not always easy to understand what has changed,
and forces maintainers to re-review the pull request from scratch. Prefer meaningful commits on top instead.
One exception to this is fixing typos or trivial renaming, in that case GitHub will show that force push had trivial
changes, make sure to not rebase on some branch at the same time, it will result in huge diff! It will also potentially
make old commits non-compilable or will cause tests fail, which hurts potential future debugging. It is better to merge `main`
into the latest commit using the GitHub button. Another exception is when major refactoring is requested that changes the
shape of the PR completely, especially if it reduces its size. In that case it is easier to re-review rather than analyzing
the diff on top of undesirable changes that will pollute the history (opening another PR removes previous context, so it is
generally not recommended, but it remains an option).

If you need to test fixes for an unknown CI issue on a branch that already has a PR created for it, create a different test
branch and push/force-push commits there until you fix it, instead of updating the PR all the time. If you notice something
is missing in the PR, convert it to draft temporarily, so it is clear to others that it is incomplete.

If there were changes requested, resolve the comments that are trivially 100% addressed by recently pushed changes, but
leave any other comments to be resolved by the person that requested those changes. Once you have addressed review
comments with responses or code changes, make sure to re-request review from that person, so they are aware that the
PR is ready for review again. If there are several unrelated changes requested, it is better to create a few commits
and push them all at once as opposed to pushing multiple commits one by one or pushing one big commit addressing all
feedback. For a few simple changes one commit is fine though.

If there are a few branches that depend on each other, you can submit a PR targeting branch other than `main`, and
once that branch is merged into `main`, the target branch in the pull request will be updated automatically. That way you
can submit a few distinct PRs from a bigger set of changes in a way that is easier for review. But this only works
if you have access to create branches in the repository.

When leaving more than one comment, make sure to post them as a review from "Files changed" tab, you can do that even if
you authored the pull request. Once done with comments, submit a review all at once, this also minimizes the amount of
distraction for maintainers.

Merging of pull requests should be done without squashing in most cases. This makes it possible to track when changes
happened, leaves moving and refactoring of files separate when done in the same PR, and helps with bisection of problematic
changes. Only trivial changes should be squashed, or those that are not reviewable for other reasons (but the above
documentation explains how to keep commits reviewable).

In general, try to maximize reviewer performance, because code is written once by you, but will be read many times by
maintainers, external auditors and anyone else who might be interested later on.
