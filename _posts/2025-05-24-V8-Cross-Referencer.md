---
title: V8 Cross Referencer
date: 2025-05-25 17:05:02 +/-0530
categories: [Chrome,Tools]
tags: [v8,tools]     # TAG names should always be lowercase
description: Tool to cross reference between V8 and Chrome Versions using Chromium Dash API.
comments: false
---
![Badge](https://hitscounter.dev/api/hit?url=https%3A%2F%2Fstreypaws.github.io%2F{{ page.url }}&label=Views&icon=eye-fill&color=%23198754&message=&style=flat&tz=UTC)

## Motivation

After completing an N-day exploit in particular V8 version, it's always a nice excercise to get it working on a Chromium build. While getting a V8 version from a Chromium version is trivial, it's difficult to do it the other way around. So, I built a tool to get all these mappings in one place so that it becomes easy to get the Chromium version from a V8 version via a simple cross reference. 

## Implementation

The tool uses `Chromium DASH API` to get information about Chromium Versions (which includes the v8 commit which is included), using this we use the v8 commit hash version to find which v8 version it corresponds to. Hence we get a direct mapping between the Chromium Version to V8 version and vide versa. 

The tool uses a single threaded download script to get json data for all the Chromium versions for all supported OSes, after which each v8 commit is translated into the corresponding V8 version and is then populated in `version.json`{: .filepath} file in `db`{: .filepath}. A cache (`cache.json`{: .filepath}) is also used to make the lookups of V8 versions via commits faster. Instead of the network request, git show could be used to get faster executions but it isn't implemented yet.

## Usage

First `git clone` the repository and inside it, create a python `virtual environment`

```bash
python3 -m venv venv
source venv/bin/activate
```
{: .nolineno }

Then install the requirements using this command 

```bash
pip3 install -r requirements.txt
```
{: .nolineno }

After which you may run the script using -

```bash
python3 main.py
```
{: .nolineno }

The `db`{: .filepath} folder consists of the versions data for all OS and channels taken from Chromium dash API and also the final versions.json which is produced after all the references have been combined and matched.

The `cache`{: .filepath} folder consists of the cached V8 lookups which do the update DB function faster since it reduces the number of HTTP requests. Github puts a rate limit on the requests so a delay of 1 second is added in the script (although this causes the update to take long time, hence the caching).

The `chrome_downloader.py`{: .filepath} is a script to download Chromium binaries in bulk. (Useful in some situations).

After running the script you will be greeted by this menu -

![Desktop View](/assets/Browser/Tools/V8_Cross_Referencer/menu.png){: width="550" height="350" }

The options are self explanatory. In the repo, most of the Chromium DASH API Data is already populated, but in case you need the more recetn versions, just use `Option 3`, it will automatically update the Database.

Let's say you chose option 2 (which is the mvp of the tool), you'll be asked for a V8 version, and upon providing so, it will present you a table with the matched chromium version across all supported OSes (Cool, right?)

![Desktop View](/assets/Browser/Tools/V8_Cross_Referencer/output.png){: width="600" height="400" }

If you wish to try out this tool, you can find it on my [Github](https://github.com/Shreyas-Penkar/V8_Cross_Referencer).

## Credits

> Hey There! If you’ve come across any bugs or have ideas for improvements, feel free to reach out to me on X!
If your suggestion proves helpful and gets implemented, I’ll gladly credit you in this dedicated Credits section. Thanks for reading!
{: .prompt-info }