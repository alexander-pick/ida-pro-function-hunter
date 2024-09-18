# IDA Pro Function Hunter
2019-2024 by Alexander Pick

## Description

[This small utility script](https://github.com/alexander-pick/ida-pro-function-hunter) was written as a helper for vulnerability analysis of blackbox binaries. It will find possible unsafe functions (the stuff you don't want to see) and other interesting spots in the binary and mark them for futher analysis. 

Furthermore it's capable of doing regex searches for intersting strings and possible hardcoded secrets in the binary. The script utilizes a toml file from gitleaks for additional signatures. This file is downloaded upon script execution [from the source repo on github](https://github.com/gitleaks/gitleaks/tree/master).

Please be aware that this script was 99% of the time used with aarch64 binaries. It works with other architectures but needs some small adjustments (i.e. call_refs).

## Usage

Open your target binary in IDA Pro and use `File` -> `Script File` to run `ida_function_hunter.py`. 

The script should complete in a couple of seconds, you will find the interesting spots set as breakpoints (press `Ctrl+Alt+B` to view the list). 

Go through the breakpoint list and enable possible interesting syscalls for further analysis. Now switch to dynamic analysis and check which of the breakpoints are reached and what state they have.

Interesting strings will be logged to IDA Pro's internal notepad for reference.

Currently the script contains an basic list of functions, feel free to add your own functions to the list or delete stuff you don't want to check at all.

## Compatibility

This script is compatible up to IDA Pro 8.x/9.x and Python 3.x.

## Motivation

I wrote the script for myself and used it for quite some time now. It was mainly designed to work with iOS and MacOSX binaries but it will work on embedded and Android native binaries as well. It's simple and portable and does the job. I found it very helpful to get an idea of the quality of a target binaries and locate possible interesting spots during assesments.

## Version History
- Moved config items to config files (see 'config.json')
- Tested with IDA 9.0

## License

MIT licensed, see LICENSE for more info.