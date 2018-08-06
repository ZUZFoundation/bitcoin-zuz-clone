<<<<<<< HEAD
Zuzcoin Core integration/staging tree
=====================================

[![Build Status](https://travis-ci.org/zuzcoin/zuzcoin.svg?branch=master)](https://travis-ci.org/zuzcoin/zuzcoin)

https://zuzcoincore.org

What is Zuzcoin?
=======
The Elements Project
=================================
This is the integration and staging tree for the Elements Project, a series of
improvements and extensions to the Bitcoin protocol.

What is the Elements Project?
-----------------
Elements is an open source collaborative project where we work on a collection
of experiments to more rapidly bring technical innovation to Bitcoin.  Elements
are features that are proposed and developed in this technical community that in
arbitrary combinations can be fashioned into sidechains.

https://github.com/ElementsProject/elementsproject.github.io

Learn more on [the Elements Project website](https://www.elementsproject.org).

What is Bitcoin?
>>>>>>> elements/alpha
----------------
https://www.bitcoin.org

Zuzcoin is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Zuzcoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
<<<<<<< HEAD
out collectively by the network. Zuzcoin Core is the name of open source
=======
out collectively by the network. Elements Alpha is the name of open source
>>>>>>> elements/alpha
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Zuzcoin Core software, see https://zuzcoin.org/en/download, or read the
[original whitepaper](https://zuzcoincore.org/zuzcoin.pdf).

<<<<<<< HEAD
License
-------

Zuzcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/zuzcoin/zuzcoin/tags) are created
regularly to indicate new official, stable release versions of Zuzcoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

The developer [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/zuzcoin-dev)
should be used to discuss complicated or controversial changes before working
on a patch set.

Developer IRC can be found on Freenode at #zuzcoin-core-dev.
=======
What is Elements Alpha?
-----------------------
https://github.com/ElementsProject/elements/tree/alpha

Elements Alpha is the Elements project's first experimental test chain.

Compared to Bitcoin itself, it adds the following features:
 * [Confidential Transactions][confidential-transactions]
 * [Segregated Witness][segregated-witness]
 * [Relative Lock Time][relative-lock-time]
 * [Schnorr Signatures][schnorr-signatures]
 * [Additional opcodes][opcodes]
 * [Deterministic Peg (pegged to Bitcoin's testnet currency).][deterministic-peg]
 * [Signed Blocks][signed-blocks]

Getting Started
---------------
See alpha-README.md for build and use instructions.
>>>>>>> elements/alpha

License
-------
Elements Alpha is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see http://opensource.org/licenses/MIT.

<<<<<<< HEAD
Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and OS X, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Zuzcoin Core's Transifex page](https://www.transifex.com/projects/p/zuzcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.

Translators should also subscribe to the [mailing list](https://groups.google.com/forum/#!forum/zuzcoin-translators).
=======
[confidential-transactions]: https://www.elementsproject.org/elements/confidential-transactions
[segregated-witness]: https://www.elementsproject.org/elements/segregated-witness
[relative-lock-time]: https://www.elementsproject.org/elements/relative-lock-time
[schnorr-signatures]: https://www.elementsproject.org/elements/schnorr-signatures
[opcodes]: https://www.elementsproject.org/elements/opcodes
[deterministic-peg]: https://www.elementsproject.org/elements/deterministic-pegs
[signed-blocks]: https://www.elementsproject.org/elements/signed-blocks
>>>>>>> elements/alpha
