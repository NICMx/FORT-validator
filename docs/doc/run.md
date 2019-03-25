---
title: Running the package
---

# {{ page.title }}

> Note: The separation between Validator and RTR server is a temporal arrangement for the Beta version.
> 
> For the sake of performance and ease of use, the two binaries will be merged by the time version 1.0.0 is released. These instructions will become obsolete then.

Create file `~/fort/update-rpki.sh`, and drop the following content into it:

{% highlight bash %}
#!/bin/bash

# TODO I'm assuming the file names will not contain whitespace for now.

# First argument: Directory containing all the TALs
TAL_DIRECTORY=$1
# Second argument: File we share with the RTR server
# (The script will also temporarily manage a file called
# "$OUTPUT_FILE.tmp")
OUTPUT_FILE=$2
# Third argument: Working directory.
# We'll store the repository and temporal files here.
WORKING_DIR=$3

# Directory where we'll store temporal ROA files, used to assemble
# $OUTPUT_FILE.tmp.
TMP_ROA_DIR=$WORKING_DIR/roa
# The local repository cache
CACHE_DIR=$WORKING_DIR/repository


mkdir -p $TMP_ROA_DIR
mkdir -p $CACHE_DIR

echo "Updating and validating the repository..."
# TODO we'd probably gain a lot of performance by running these in
# parallel
for TAL_FILE in $TAL_DIRECTORY/*; do
	echo "  Handling TAL $TAL_FILE..."
	/usr/local/bin/rpki_validator \
		--tal $TAL_FILE \
		--local-repository $CACHE_DIR \
		--roa-output-file $TMP_ROA_DIR/$(basename $TAL_FILE .tal).roa.tmp \
		> /dev/null
done

echo "Joining all the generated ROA files..."

# Make sure it exists. Otherwise the mv explodes
touch $OUTPUT_FILE.tmp
# Make sure $TMP_ROA_DIR/*.tmp expands, even if there are no files.
shopt -s nullglob

for TMP_ROA_FILE in $TMP_ROA_DIR/*.tmp; do
	echo "  Joining file $TMP_ROA_FILE..."
	cat $TMP_ROA_FILE >> $OUTPUT_FILE.tmp
	rm $TMP_ROA_FILE
done

echo "Replacing old ROA file with new one..."
# (Needs to be done last for the sake of atomicity.)
mv $OUTPUT_FILE.tmp $OUTPUT_FILE

echo "Done."
{% endhighlight %}

Grant it executable permissions:

{% highlight bash %}
$ chmod +x ~/fort/update-rpki.sh
{% endhighlight %}

Place your `.tal` files in `~/fort/tal`:

{% highlight bash %}
$ mv <?> ~/fort/tal
{% endhighlight %}

Then create a cron job (`crontab -e`), running the script above every hour:

	0 * * * * ~/fort/update-rpki.sh ~/fort/tal /tmp/fort/roas.csv /tmp/fort

Now the RTR Server can serve the ROAs:

{% highlight bash %}
$ cat rtr-config.json
{
	"listen": {
		"address": "::1",
		"port": "8323",
		"queue": 10
	},
	"vrps": {
		"location": "/tmp/fort/roas.csv",
		"checkInterval": 60
	}
}
$ rtr_server -f rtr-config.json
{% endhighlight %}
