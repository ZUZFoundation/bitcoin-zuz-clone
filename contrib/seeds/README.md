# Seeds

Utility to generate the seeds.txt list that is compiled into the client
<<<<<<< HEAD
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and other utilities in [contrib/seeds](/contrib/seeds)).

Be sure to update `PATTERN_AGENT` in `makeseeds.py` to include the current version,
and remove old versions as necessary (at a minimum when GetDesireableServiceFlags
changes its default return value, as those are the services which seeds are added
to addrman with).

The seeds compiled into the release are created from sipa's DNS seed data, like this:

    curl -s http://zuzcoin.sipa.be/seeds.txt.gz | gzip -dc > seeds_main.txt
    python3 makeseeds.py < seeds_main.txt > nodes_main.txt
    python3 generate-seeds.py . > ../../src/chainparamsseeds.h

## Dependencies

Ubuntu:

    sudo apt-get install python3-dnspython
=======
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and [share/seeds](/share/seeds)).

The 512 seeds compiled into the 0.10 release were created from sipa's DNS seed data, like this:

	curl -s http://bitcoin.sipa.be/seeds.txt | makeseeds.py
>>>>>>> elements/alpha
