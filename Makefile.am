# GNU wants us to include some files that we really don't want; therefore
# "foreign". The files are
#
# - AUTHORS: This should be inferred from the (automatic) git history, not some
#   error prone, manually-maintained file!
# - ChangeLog: This is included in the main page of the site, which can be found
#   in the gh-pages branch. Don't want to (nor should I) repeat myself.
# - NEWS: Same as ChangeLog.
# - README: We prefer the much gayer "README.md" version, so no thanks.
#
# Man, GNU conventions need a 21 century overhaul badly.
AUTOMAKE_OPTIONS = foreign

SUBDIRS = src man test

EXTRA_DIST  = examples/tal/afrinic.tal
EXTRA_DIST += examples/tal/apnic.tal
EXTRA_DIST += examples/tal/lacnic.tal
EXTRA_DIST += examples/tal/ripe.tal
EXTRA_DIST += examples/config.json
EXTRA_DIST += examples/demo.slurm
