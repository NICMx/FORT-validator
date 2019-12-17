#!/bin/sh

# Setup script to ease FORT validator configuration (or even another RP),
# expects one arg:
#   $ ./fort_setup.sh TALS_PATH
#
# ADVISE: Preferably, run this script with the same user what will run FORT
# validator. It's recommended that the user has write permission in /var/cache,
# since the script will try to create a directory there (see
# https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s05.html).
# 
# TALS_PATH must be an existent directory path, where the five RIRs TALs will
# be downloaded.
#
# The main objective of this script is to simplify ARIN TAL download, by
# explicitly agreeing its RPA. The rest of the actions are just facilitators to
# run FORT validator.
#
# The script does the following:
# 1. Display message to agree ARIN RPA.
# 2. If agreed, download ARIN TAL to TALS_PATH arg.
# 3. Download the rest of the TALs to TALS_PATH arg.
# 4. Try to create directory '/var/cache/fort/repository', on error create
#    '/tmp/fort/repository'.
# 5. Create configuration file with 'tal' and 'local-repository' members,
#    with a value of TALS_PATH (absolute path) and the directory path created
#    at the previous step.
# 6. Display FORT validator execution examples:
#    - Using the created configuration file (uses the arg '-f').
#    - Using the values of the configuration file (uses the args '--tal' and
#      '--local-repository').

exit_on_err()
{
  if ! [ $1 ] ; then
    echo "$2"
    exit 1
  fi
}

# Timeout for http requests
DOWN_TIME=20

get_tal()
{
  echo ""
  echo "Fetching $1 TAL..."
  wget -O "$2" -T $DOWN_TIME $3
  RES=$?
  exit_on_err "\"$RES\" = \"0\"" "Couldn't fetch $1 TAL, try again."
}

# Validate expected args
exit_on_err "$# -gt 0" 'Usage: '"$0"' TALS_PATH.\nTALS_PATH must be an existent directory path.'
TMP=`echo "$1"`
if ! [ -d "$TMP" ] ; then
  echo "Path '$TMP' isn't a directory."
  exit 1
fi
if ! [ -w "$TMP" ] ; then
  echo "Write permission denied on path '$TMP'."
  exit 1
fi

# Define download command
if type wget >/dev/null 2>&1 ; then
  echo ""
else
  echo "Couldn't find 'wget' program; I need it to fetch the TALs."
  exit 1
fi

# Get the absolute path, in case the configuration file is placed elsewhere
TALS_LOC=$TMP
TMP=$(readlink -f "$TALS_LOC")
if [ "$?" = "0" ] ; then
  TALS_LOC="$TMP"
  TMP=""
fi

# Declare variables
GITHUB_TALS="https://raw.githubusercontent.com/NICMx/FORT-validator/master/examples/tal"
ACCEPT="no"
REPO_DIR="/var/cache/fort/repository"
CONF_FILE="fort-config.json"
ARIN_TAL="https://www.arin.net/resources/manage/rpki/arin-rfc7730.tal"

# Agree ARIN RPA. Exit on denial or unknown response, download otherwise.
echo "Please download and read ARIN Relying Party Agreement (RPA) from https://www.arin.net/resources/manage/rpki/rpa.pdf"
echo ""
echo -n "Once you've read and if you agree ARIN RPA, type \"yes\" to proceed with ARIN's TAL download: "
read ACCEPT
exit_on_err "\"$(echo $ACCEPT | tr '[:upper:]' '[:lower:]')\" = \"yes\"" '\nYou haven'"'"'t agreed ARIN RPA! You can manually download its TAL or try running this script again.\n\nWe strongly advise to download ARIN TAL so that the Relying Party (validator) can validate the whole RPKI.'

get_tal "ARIN" "$TALS_LOC/arin-rfc7730.tal" $ARIN_TAL

# Get the rest of the TALs
echo ""
echo "Fetching the rest of the TALs"
get_tal "LACNIC" "$TALS_LOC/lacnic.tal" "$GITHUB_TALS/lacnic.tal"
get_tal "RIPE" "$TALS_LOC/ripe.tal" "$GITHUB_TALS/ripe.tal"
get_tal "AFRINIC" "$TALS_LOC/afrinic.tal" "$GITHUB_TALS/afrinic.tal"
get_tal "APNIC" "$TALS_LOC/apnic.tal" "$GITHUB_TALS/apnic.tal"

# Try to create local repository directory
mkdir -p -v $REPO_DIR
if ! [ "$?" = "0" ] ; then
  echo "Couldn't create dir $REPO_DIR."
  REPO_DIR="/tmp/fort/repository"
  echo ""
  echo "Fallback, trying to create dir $REPO_DIR."
  mkdir -p -v $REPO_DIR
  if ! [ "$?" = "0" ] ; then
    echo "Couldn't create dir $REPO_DIR."
    REPO_DIR=""
  fi
fi

# Create or overwrite configuration file
touch $CONF_FILE
echo "{ " > $CONF_FILE
if ! [ -z "$REPO_DIR" ] ; then
  echo "  \"local-repository\": \"$REPO_DIR\"," >> $CONF_FILE
fi
echo "  \"tal\": \"$TALS_LOC\"" >> $CONF_FILE
echo "} " >> $CONF_FILE

# Display actions summary and usage examples
echo ""
echo "------------------------------------------------------"
if [ -z "$TMP" ] ; then
  echo "--------------------   Success!   --------------------"
else
  echo "-------------   Done (with warnings)!   --------------"
fi
echo "------------------------------------------------------"
echo ""
echo "- The five RIRs TAL's were downloaded to '$TALS_LOC'."
if ! [ -z "$REPO_DIR" ] ; then
  echo "- The directory $REPO_DIR was created, so it can be used as the local repository."
fi
if ! [ -z "$TMP" ] ; then
  echo "- WARNING! Couldn't get absolute path of '$TALS_LOC', so I utilized this path '$TALS_LOC' at the configuration file"
fi
echo "- The configuration file '$CONF_FILE' was created with the following content:"
cat $CONF_FILE
echo ""
echo "- This configuration file can be utilized with FORT validator, e.g.:"
echo "  \$ fort -f \"$CONF_FILE\""
echo "- Or its members can be utilized as FORT validator arguments, e.g.:"
echo -n "  \$ fort --tal \"$TALS_LOC\"" && ! [ -z "$REPO_DIR" ] && echo " --local-repository \"$REPO_DIR\""
echo "" 

